use smoltcp::socket::TcpSocket;
use smoltcp::socket::TcpState;
use smoltcp::socket::SocketHandle;
use smoltcp::socket::SocketSet;
use smoltcp::wire::IpEndpoint;
use smoltcp::Result;
use smoltcp::Error;
use smoltcp::phy::Device;
use smoltcp::iface::EthernetInterface;
use smoltcp::time::Instant;

use byteorder::{ByteOrder, NetworkEndian};
use generic_array::GenericArray;

use core::convert::TryFrom;
use core::convert::TryInto;
use core::cell::RefCell;

use p256::{EncodedPoint, ecdh::EphemeralSecret};
use ccm::consts::*;

use nom::bytes::complete::take;
use nom::error::ErrorKind;
use nom::combinator::complete;

use alloc::vec::Vec;
use heapless::Vec as HeaplessVec;

use crate::tls_packet::*;
use crate::parse::{
    parse_tls_repr,
    parse_inner_plaintext_for_handshake,
    get_content_type_inner_plaintext
};
use crate::buffer::TlsBuffer;
use crate::session::{Session, TlsRole, DiffieHellmanPublicKey, DiffieHellmanPrivateKey};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub(crate) enum TlsState {
    DEFAULT,            // The default state of the TLS socket
    // Client state machine diagram
    CLIENT_START,
    WAIT_SH,
    WAIT_EE,
    WAIT_CERT_CR,
    CLIENT_WAIT_CERT,
    CLIENT_WAIT_CV,
    CLIENT_WAIT_FINISHED,
    SERVER_COMPLETED,   // Additional state, for client to send Finished after server Finished
    CLIENT_CONNECTED,
    // Server state machine diagram
    SERVER_START,
    NEGOTIATED,
    WAIT_FLIGHT,
    SERVER_WAIT_CERT,
    SERVER_WAIT_CV,
    SERVER_WAIT_FINISHED,
    SERVER_CONNECTED
}

pub struct TlsSocket<'a, 'b, 'c>
{
    // Locally owned SocketSet, solely containing 1 TCP socket
    sockets: SocketSet<'a, 'b, 'c>,
    tcp_handle: SocketHandle,
    rng: &'b mut dyn crate::TlsRng,
    session: RefCell<Session<'b>>,
}

impl<'a, 'b, 'c> TlsSocket<'a, 'b, 'c> {
    pub fn new(
        tcp_socket: TcpSocket<'b>,
        rng: &'b mut dyn crate::TlsRng,
        certificate_with_key: Option<(
            crate::session::CertificatePrivateKey,
            Vec<&'b [u8]>
        )>
    ) -> Self
    {
        let socket_set_entries: [_; 1] = Default::default();
        let mut sockets = SocketSet::new(socket_set_entries);
        let tcp_handle = sockets.add(tcp_socket);
        TlsSocket {
            sockets,
            tcp_handle,
            rng,
            session: RefCell::new(
                Session::new(TlsRole::Unknown, certificate_with_key)
            ),
        }
    }

    pub fn connect<T, U>(
        &mut self,
        remote_endpoint: T,
        local_endpoint: U,
    ) -> Result<()>
    where
        T: Into<IpEndpoint>,
        U: Into<IpEndpoint>,
    {
        let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
        let mut session = self.session.borrow_mut();

        // Start TCP handshake
        if !tcp_socket.is_open() {
            tcp_socket.connect(remote_endpoint, local_endpoint)?;
            // Start TLS handshake if TCP handshake will commence
            session.connect(
                tcp_socket.remote_endpoint(),
                tcp_socket.local_endpoint()
            );
        } else {
            // Also start TLS handshake if for some reason TCP is ready,
            // and TLS is idle
            if session.get_tls_state() == TlsState::DEFAULT {
                session.connect(
                    tcp_socket.remote_endpoint(),
                    tcp_socket.local_endpoint()
                );
            }
        }

        Ok(())
    }

    pub fn listen<T>(
        &mut self,
        local_endpoint: T
    ) -> Result<()>
    where
        T: Into<IpEndpoint>
    {
        // Listen from TCP socket
        let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
        tcp_socket.listen(local_endpoint)?;

        // Update tls session to server_start
        let mut session = self.session.borrow_mut();
        session.listen();

        Ok(())
    }

    pub fn update_handshake<DeviceT>(
        &mut self,
        iface: &mut EthernetInterface<DeviceT>,
        now: Instant
    ) -> Result<bool>
    where
        DeviceT: for<'d> Device<'d>
    {
        // Poll the TCP socket, no matter what
        let propagated_poll = iface.poll(&mut self.sockets, now)?;

        // Handle TLS handshake through TLS states
        let tls_state = {
            self.session.borrow().get_tls_state()
        };

        let need_send_alert = {
            self.session.borrow().get_need_send_alert()
        };

        // Check TCP socket/ TLS session
        {
            let tcp_state = self.sockets.get::<TcpSocket>(self.tcp_handle).state();

            // Close TCP socket if necessary
            if tcp_state == TcpState::Established && tls_state == TlsState::DEFAULT {
                self.sockets.get::<TcpSocket>(self.tcp_handle).close();
                return Ok(propagated_poll);
            }

            // Skip handshake processing if it is already completed
            // However, redo TCP handshake if TLS socket is trying to connect and
            // TCP socket is not connected <= seems like a bad piece of idea to me
            // Reset TLS state to DEFAULT if TCP session is interrupted
            // This is to close off hanged TLS sockets, when its dependent TCP session
            // has already ended.
            if tcp_state != TcpState::Established {
                use TlsState::*;
                match tls_state {
                    // Do nothing on the starting states
                    // Namely those immediate precedes TCP handshake,
                    // as handshake can legitimately be incomplete
                    DEFAULT |
                    SERVER_START => {},

                    // Attempt to reconnect if the socket went down before TLS socket sent anything
                    CLIENT_START => {
                        let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
                        let session = self.session.borrow();
                        if !tcp_socket.is_open() {
                            log::info!("Socket closed initially");
                            tcp_socket.connect(
                                session.get_remote_endpoint(),
                                session.get_local_endpoint()
                            )?;                        
                        }
                    }

                    // For any other functioning state, the TCP connection being not
                    // established should imply that the TLS connection had been derailed
                    // Reset TLS state to DEFAULT to allow terminate a dead link
                    _ => {
                        let mut session = self.session.borrow_mut();
                        session.reset_state();
                        log::info!("TLS socket resets after TCP socket closed");
                    }
                }

                // Terminate the procedure, as no processing is necessary
                return Ok(propagated_poll);
            }
        }

        // Send alert to start terminating TLS session if necessary
        if let Some(alert) = need_send_alert {
            match tls_state {
                // Client side socket:
                // States that expects plaintext payload
                TlsState::WAIT_SH | TlsState::SERVER_START => {
                    // Send the cooresponding alert in plaintext
                    let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
                    tcp_socket.send(
                        |data| {
                            // Set up a TLS buffer on the internal buffer of TCP socket
                            let mut buffer = TlsBuffer::new(data);
                            // Instantiate a TLS bytes-representation with pre-determined alert
                            let tls_repr = TlsRepr::new().alert(alert);
                            if buffer.enqueue_tls_repr(tls_repr).is_err() {
                                return (0, ())
                            }

                            let slice: &[u8] = buffer.into();
                            (slice.len(), ())
                        }
                    )?;
                },
                // States that expects enrypted payload using handshake secret
                TlsState::WAIT_EE |
                TlsState::WAIT_CERT_CR |
                TlsState::CLIENT_WAIT_CERT |
                TlsState::CLIENT_WAIT_CV |
                TlsState::CLIENT_WAIT_FINISHED |
                TlsState::SERVER_COMPLETED |
                TlsState::NEGOTIATED |
                TlsState::WAIT_FLIGHT |
                TlsState::SERVER_WAIT_CERT |
                TlsState::SERVER_WAIT_CV => {
                    // Send the corresponding alert in ciphertext using handshake secret
                    let severity: u8 = match alert {
                        AlertType::CloseNotify | AlertType::UserCanceled => {
                            1
                        },
                        _ => 2
                    };
                    let mut alert_array: [u8; 3] = [
                        severity,
                        u8::try_from(alert).unwrap(),
                        21              // Alert content type
                    ];
                    self.send_application_slice(&mut alert_array)?;
                },
                // States that expects enrypted payload using application data secret
                TlsState::CLIENT_CONNECTED |
                TlsState::SERVER_WAIT_FINISHED |
                TlsState::SERVER_CONNECTED => {
                    // Send the corresponding alert in ciphertext using application data secret
                    // Sending order:
                    // 1. Associated data/ TLS Record layer
                    // 2. Encrypted { Alert }
                    // 3. Authentication tag (16 bytes for all supported AEADs)
                    let mut associated_data: [u8; 5] = [
                        0x17,           // Application data
                        0x03, 0x03,     // TLS 1.3 record disguised as TLS 1.2
                        0x00, 0x00      // Length of encrypted data, yet to be determined conveniently
                    ];

                    NetworkEndian::write_u16(&mut associated_data[3..5],
                        2                                   // Payload length
                        + 1                                 // Content type length
                        + 16                                // Auth tag length
                    );

                    // Alert: Warning (1) , Close notify (0)
                    let severity: u8 = match alert {
                        AlertType::CloseNotify | AlertType::UserCanceled => {
                            1
                        },
                        _ => 2
                    };
                    let mut alert_array: [u8; 3] = [
                        severity,
                        u8::try_from(alert).unwrap(),
                        21              // Alert content type
                    ];
                    
                    let mut session = self.session.borrow_mut();
                    let tag = session.encrypt_application_data_in_place_detached(
                        &associated_data,
                        &mut alert_array
                    ).unwrap();
                    session.increment_local_sequence_number();

                    let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
                    if !tcp_socket.can_send() {
                        return Err(Error::Illegal);
                    }

                    tcp_socket.send_slice(&associated_data)?;
                    tcp_socket.send_slice(&alert_array)?;
                    tcp_socket.send_slice(&tag)?;
                },
                // Other states, such as client_start and default should never send alert
                // These stages are too early to raise exceptions
                _ => unreachable!()
            }

            // Finally, revert the FSM to DEFAULT to signal an invokation of
            // `close()` to the TCP socket
            self.session.borrow_mut().reset_state();

            return Ok(propagated_poll);
        }

        // Handle TLS handshake through TLS states
        match tls_state {
            // Do nothing on the default state
            // Socket has not been assigned to be a client or server
            TlsState::DEFAULT => {},
            // Initiate TLS handshake
            TlsState::CLIENT_START => {
                // Prepare field that is randomised,
                // Supply it to the TLS repr builder.
                let ecdh_secret = EphemeralSecret::random(&mut self.rng);
                let x25519_secret = x25519_dalek::EphemeralSecret::new(&mut self.rng);
                let mut random: [u8; 32] = [0; 32];
                let mut session_id: [u8; 32] = [0; 32];
                self.rng.fill_bytes(&mut random);
                self.rng.fill_bytes(&mut session_id);
                let repr = TlsRepr::new()
                    .client_hello(&ecdh_secret, &x25519_secret, random, session_id.clone());

                {
                    let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
                    let mut session = self.session.borrow_mut();
                    tcp_socket.send(
                        |data| {
                            // Enqueue tls representation without extra allocation
                            let mut buffer = TlsBuffer::new(data);
                            if buffer.enqueue_tls_repr(repr).is_err() {
                                return (0, ())
                            }
                            let slice: &[u8] = buffer.into();

                            // Update the session
                            // No sequence number calculation in CH
                            // because there is no encryption
                            // Still, data needs to be hashed
                            session.client_update_for_ch(
                                ecdh_secret,
                                x25519_secret,
                                session_id,
                                &slice[5..]
                            );

                            // Finally send the data
                            (slice.len(), ())
                        }
                    )?;
                }
            },

            // TLS Client wait for Server Hello
            // No need to send anything
            TlsState::WAIT_SH => {},

            // TLS Client wait for certificate from TLS server
            // No need to send anything
            // Note: TLS server should normally send SH alongside EE
            // TLS client should jump from WAIT_SH directly to WAIT_CERT_CR directly.
            TlsState::WAIT_EE => {},

            // TLS Client wait for server's certificate/ certificate request
            // No need to send anything
            TlsState::WAIT_CERT_CR => {},

            // TLS Client wait for server's certificate after receiveing a request
            // No need to send anything
            TlsState::CLIENT_WAIT_CERT => {},

            // TLS Client wait for server's certificate cerify
            // No need to send anything
            TlsState::CLIENT_WAIT_CV => {},

            // Last step of server authentication
            // TLS Client wait for server's Finished handshake
            // No need to send anything
            TlsState::CLIENT_WAIT_FINISHED => {}

            // Send client Finished to end handshake
            // Also send certificate and certificate verify before client Finished if
            // server sent a CertificateRequest beforehand
            TlsState::SERVER_COMPLETED => {
                // Certificate & CertificateVerify
                let need_to_send_client_cert = {
                    self.session.borrow().need_to_send_client_certificate()
                };
                if need_to_send_client_cert {
                    let (certificates_total_length, buffer_vec) = {
                        let session = self.session.borrow();
                        let mut buffer_vec: Vec<u8> = Vec::new();
                        let certificates = session
                            .get_private_certificate_slices()
                            .clone();
    
                        // Handshake level, client certificate byte followed by length (u24)
                        // Certificate struct:
                        // request_context = X509: 0 (u8),
                        // certificate_list to be determined (u24)
                        let mut certificates_total_length: u32 = 0;
    
                        // Append place holder bytes (8 of them) in the buffer vector
                        // Simpily copy the the headers back into the vector
                        // when all certificates are appended into the vector
                        buffer_vec.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
    
                        // Certificate Entry struct(s)
                        if let Some(certificate_list) = certificates {
                            for cert in certificate_list.iter() {
                                // cert_data length, to be determined (u24)
                                let mut cert_data_length: [u8; 3] = [0, 0, 0];
                                // extensions: no extension needed
                                let extension: [u8; 2] = [0, 0];
    
                                let certificate_length: u32 = u32::try_from(cert.len()).unwrap();
    
                                NetworkEndian::write_u24(
                                    &mut cert_data_length,
                                    certificate_length
                                );
    
                                // Update length in Certificate struct
                                certificates_total_length += 
                                    // cert_data (len & data) AND extension (len & data)
                                    3 + certificate_length + 2 + 0;
    
                                buffer_vec.extend_from_slice(&cert_data_length);
                                buffer_vec.extend_from_slice(cert);
                                buffer_vec.extend_from_slice(&extension);
                            }
                        }
    
                        // Write total certificate length into Certificate struct
                        NetworkEndian::write_u24(
                            &mut buffer_vec[5..8],
                            certificates_total_length
                        );
    
                        // Write the length of the entire handshake
                        NetworkEndian::write_u24(
                            &mut buffer_vec[1..4],
                            // 4 bytes for the Certificate struct header
                            certificates_total_length + 4
                        );
    
                        // Inner plaintext: record type 
                        buffer_vec.push(22);
                        (certificates_total_length, buffer_vec)
                    };

                    self.send_application_slice(&mut buffer_vec.clone())?;
                    // Update session
                    let buffer_vec_length = buffer_vec.len();

                    {
                        self.session.borrow_mut()
                            .client_update_for_certificate_in_server_completed(
                            &buffer_vec[..(buffer_vec_length-1)]
                        );
                    }

                    // Send a CertificateVerify as well if any certificates
                    // were just sent by the client
                    if certificates_total_length != 0 {
                        // Serialize CertificateVerify

                        // Handshake bytes:
                        // msg_type = 15, CertificateVerify (u8)
                        // handshake_data_length = to be determined (u24)
                        // signature algorithm (u16)
                        // signature_length (u16)
                        // signature, the rest

                        let mut verify_buffer_vec: Vec<u8> = Vec::new();
                        // Leave bytes from Handshake struct as placeholders
                        verify_buffer_vec.extend_from_slice(&[
                            15,
                            0, 0, 0,
                            0, 0,
                            0, 0
                        ]);
                        {
                            let session = self.session.borrow();
                            let (sig_alg, signature) = session
                                .get_certificate_verify_signature(
                                    &mut self.rng,
                                    TlsRole::Client
                                );
                            
                            let signature_length: u16 = u16::try_from(signature.len()).unwrap();
                            NetworkEndian::write_u24(
                                &mut verify_buffer_vec[1..4],
                                (signature_length + 4).into()
                            );
                            NetworkEndian::write_u16(
                                &mut verify_buffer_vec[4..6],
                                sig_alg.try_into().unwrap()
                            );
                            NetworkEndian::write_u16(
                                &mut verify_buffer_vec[6..8],
                                signature_length
                            );
                            verify_buffer_vec.extend_from_slice(&signature);
                        }
                        // Push content byte (handshake: 22)
                        verify_buffer_vec.push(22);

                        self.send_application_slice(&mut verify_buffer_vec.clone())?;
                        // Update session
                        let cert_verify_len = verify_buffer_vec.len();

                        {
                            self.session.borrow_mut()
                                .client_update_for_cert_verify_in_server_completed(
                                    &verify_buffer_vec[..(cert_verify_len-1)]
                                );
                        }
                    }
                }

                // Client Finished
                let inner_plaintext: HeaplessVec<u8, U64> = {
                    let verify_data = self.session.borrow()
                        .get_client_finished_verify_data();
                    let mut handshake_header: [u8; 4] = [20, 0, 0, 0];
                    NetworkEndian::write_u24(
                        &mut handshake_header[1..4],
                        u32::try_from(verify_data.len()).unwrap()
                    );
                    let mut buffer = HeaplessVec::from_slice(&handshake_header).unwrap();
                    buffer.extend_from_slice(&verify_data).unwrap();
                    // Inner plaintext: record type
                    buffer.push(22).unwrap();
                    buffer
                };
                self.send_application_slice(&mut inner_plaintext.clone())?;

                let inner_plaintext_length = inner_plaintext.len();
                self.session.borrow_mut()
                    .client_update_for_server_completed(&inner_plaintext[..(inner_plaintext_length-1)]);
            }

            // There is no need to care about handshake if it was completed
            TlsState::CLIENT_CONNECTED => {
                return Ok(propagated_poll);
            }

            // This state waits for Client Hello handshake from a client
            // There is nothing to send
            TlsState::SERVER_START => {}

            // Respond to a Client Hello initiation with:
            // - Server Hello
            // - Encrypted Extensions
            // - (Possible) Certificate Request
            // - Certificate
            // - CertificateVerify
            // - Finished
            TlsState::NEGOTIATED => {
                let mut random: [u8; 32] = [0; 32];
                self.rng.fill_bytes(&mut random);
                let (session_id, cipher_suite, server_ecdhe_public_key) = {
                    let session = self.session.borrow();
                    (
                        session.get_session_id(),
                        session.get_cipher_suite(),
                        session.get_server_ecdhe_public_key()
                    )
                };
                let ecdhe_private_key = match server_ecdhe_public_key {
                    DiffieHellmanPublicKey::SECP256R1 { .. } => {
                        DiffieHellmanPrivateKey::SECP256R1 {
                            ephemeral_secret: {
                                p256::ecdh::EphemeralSecret::random(&mut self.rng)
                            }
                        }
                    },
                    DiffieHellmanPublicKey::X25519 { .. } => {
                        DiffieHellmanPrivateKey::X25519 {
                            ephemeral_secret: {
                                x25519_dalek::EphemeralSecret::new(&mut self.rng)
                            }
                        }
                    }
                };
                let ecdhe_public_key = ecdhe_private_key.to_public_key();

                // Construct and send SH
                let repr = TlsRepr::new().server_hello(
                    &random,
                    &session_id,
                    cipher_suite,
                    ecdhe_public_key
                );
                {
                    let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
                    let mut session = self.session.borrow_mut();
                    tcp_socket.send(
                        |data| {
                            // Enqueue the TLS representation
                            let mut buffer = TlsBuffer::new(data);
                            if buffer.enqueue_tls_repr(repr).is_err() {
                                return (0, ())
                            }
                            let slice: &[u8] = buffer.into();

                            // Update session after sending only SH
                            session.server_update_for_server_hello(
                                ecdhe_private_key,
                                &slice[5..]
                            );

                            // Send the data
                            (slice.len(), ())
                        }
                    )?;
                }

                log::info!("sent server hello");

                // Construct and send minimalistic EE
                let inner_plaintext: [u8; 7] = [
                    0x08,               // EE type
                    0x00, 0x00, 0x02,   // Length: 2
                    0x00, 0x00,         // Length of extensions: 0
                    22                  // Content type of InnerPlainText
                ];
                self.send_application_slice(&mut inner_plaintext.clone())?;

                let inner_plaintext_length = inner_plaintext.len();
                {
                    let mut session = self.session.borrow_mut();
                    session.server_update_for_encrypted_extension(
                        &inner_plaintext[..(inner_plaintext_length-1)]
                    );
                }

                log::info!("sent encrypted extension");

                // TODO: Option to allow a certificate request

                // Construct and send server certificate handshake content
                let inner_plaintext = {
                    let mut inner_plaintext: Vec<u8> = Vec::new();
                    let session = self.session.borrow();
                    let certificates = session.get_private_certificate_slices().clone();
                    
                    // Handshake level, client certificate byte followed by length (u24)
                    // Certificate struct:
                    // request_context = X509: 0 (u8),
                    // certificate_list to be determined (u24)
                    let mut certificates_total_length: u32 = 0;

                    // Append place holder bytes (8 of them) in the buffer vector
                    // Simpily copy the the headers back into the vector
                    // when all certificates are appended into the vector
                    inner_plaintext.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);

                    // Certificate Entry struct(s)
                    if let Some(certificate_list) = certificates {
                        for cert in certificate_list.iter() {
                            // cert_data length, to be determined (u24)
                            let mut cert_data_length: [u8; 3] = [0, 0, 0];
                            // extensions: no extension needed
                            let extension: [u8; 2] = [0, 0];

                            let certificate_length: u32 = u32::try_from(cert.len()).unwrap();

                            NetworkEndian::write_u24(
                                &mut cert_data_length,
                                certificate_length
                            );

                            // Update length in Certificate struct
                            certificates_total_length += 
                                // cert_data (len & data) AND extension (len & data)
                                3 + certificate_length + 2 + 0;

                            inner_plaintext.extend_from_slice(&cert_data_length);
                            inner_plaintext.extend_from_slice(cert);
                            inner_plaintext.extend_from_slice(&extension);
                        }
                    }

                    // Write total certificate length into Certificate struct
                    NetworkEndian::write_u24(
                        &mut inner_plaintext[5..8],
                        certificates_total_length
                    );

                    // Write the length of the entire handshake
                    NetworkEndian::write_u24(
                        &mut inner_plaintext[1..4],
                        // 4 bytes for the Certificate struct header
                        certificates_total_length + 4
                    );

                    // Inner plaintext: record type 
                    inner_plaintext.push(22);
                    inner_plaintext
                };

                self.send_application_slice(&mut inner_plaintext.clone())?;
                let inner_plaintext_length = inner_plaintext.len();
                // Update session
                {
                    self.session.borrow_mut()
                        .server_update_for_sent_certificate(&inner_plaintext[..(inner_plaintext_length-1)]);
                }
                log::info!("sent certificate");

                // Construct and send certificate verify
                let inner_plaintext = {
                    let mut inner_plaintext = Vec::new();
                    inner_plaintext.extend_from_slice(&[
                        15,
                        0, 0, 0,
                        0, 0,
                        0, 0
                    ]);
                    let session = self.session.borrow();
                    let (sig_alg, signature) = session.get_certificate_verify_signature(
                        &mut self.rng,
                        TlsRole::Server
                    );
                    let signature_length: u16 = u16::try_from(signature.len()).unwrap();
                    NetworkEndian::write_u24(
                        &mut inner_plaintext[1..4],
                        (signature_length + 4).into()
                    );
                    NetworkEndian::write_u16(
                        &mut inner_plaintext[4..6],
                        sig_alg.try_into().unwrap()
                    );
                    NetworkEndian::write_u16(
                        &mut inner_plaintext[6..8],
                        signature_length
                    );
                    inner_plaintext.extend_from_slice(&signature);
                    inner_plaintext.push(22);   // Content type byte
                    inner_plaintext
                };

                self.send_application_slice(&mut inner_plaintext.clone())?;

                let inner_plaintext_length = inner_plaintext.len();
                {
                    self.session.borrow_mut()
                        .server_update_for_sent_certificate_verify(
                            &inner_plaintext[..(inner_plaintext_length-1)]
                        );
                }
                log::info!("sent certificate verify");

                // Construct and send server finished
                let inner_plaintext: HeaplessVec<u8, U64> = {
                    let verify_data = self.session.borrow()
                        .get_server_finished_verify_data();
                    let mut handshake_header: [u8; 4] = [20, 0, 0, 0];
                    NetworkEndian::write_u24(
                        &mut handshake_header[1..4],
                        u32::try_from(verify_data.len()).unwrap()
                    );
                    let mut buffer = HeaplessVec::from_slice(&handshake_header).unwrap();
                    buffer.extend_from_slice(&verify_data).unwrap();
                    // Inner plaintext: record type
                    buffer.push(22).unwrap();
                    buffer
                };
                self.send_application_slice(&mut inner_plaintext.clone())?;

                let inner_plaintext_length = inner_plaintext.len();
                {
                    self.session.borrow_mut()
                        .server_update_for_server_finished(&inner_plaintext[..(inner_plaintext_length-1)]);                    
                }
                log::info!("sent client finished");
            }

            // There is no need to care about handshake if it was completed
            // This is to prevent accidental dequeing of application data
            TlsState::SERVER_CONNECTED => {
                return Ok(propagated_poll);
            }

            // Other states
            _ => {}
        }

        // Read for TLS packet
        // Proposition: Decouple all data from TLS record layer before processing
        //      Recouple a brand new TLS record wrapper
        // Use peek & recv to avoid buffer allocation
        {
            let tls_repr_vec = {
                let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);

                // Check if there are bytes enqueued in the recv buffer
                // No need to do further dequeuing if there are no receivable bytes
                if !tcp_socket.can_recv() {
                    return Ok(propagated_poll)
                }

                // Peak into the first 5 bytes (TLS record layer)
                // This tells the length of the entire record
                let length = match tcp_socket.peek(5) {
                    Ok(bytes) => NetworkEndian::read_u16(&bytes[3..5]),
                    _ => return Ok(propagated_poll)
                };

                // Recv the entire TLS record
                tcp_socket.recv(
                    |buffer| ((length + 5).into(), Vec::from(&buffer[..(length + 5).into()]))
                ).unwrap()
            };

            // Parse the bytes representation of a TLS record
            let (repr_slice, mut repr) = match parse_tls_repr(&tls_repr_vec) {
                Ok((_, (repr_slice, repr))) => (repr_slice, repr),
                _ => return Ok(propagated_poll)
            };

            // Process record base on content type
            log::info!("Record type: {:?}", repr.content_type);

            // Handle TLS represenatation according to the content type:
            // Handshake & ChangeCipherSpec: Directly process the handshake
            // Alert: Reset session immediately
            // ApplicationData: Decrypt and then handle, with similar criteria
            // Reject invalid contents by invalidating the TLS session
            match repr.content_type {
                TlsContentType::ApplicationData => {
                    log::info!("Found application data");
                    // Take the payload out of TLS Record and decrypt
                    let mut app_data = repr.payload.take().unwrap();
                    let mut associated_data = [0; 5];
                    associated_data[0] = repr.content_type.into();
                    NetworkEndian::write_u16(
                        &mut associated_data[1..3],
                        repr.version.into()
                    );
                    NetworkEndian::write_u16(
                        &mut associated_data[3..5],
                        repr.length
                    );
                    {
                        let mut session = self.session.borrow_mut();
                        session.decrypt_in_place_detached(
                            &associated_data,
                            &mut app_data
                        ).unwrap();
                        session.increment_remote_sequence_number();
                    }
    
                    // Discard last 16 bytes (auth tag)
                    let inner_plaintext = &app_data[..app_data.len()-16];
                    let (inner_content_type, begin_zero) = get_content_type_inner_plaintext(
                        inner_plaintext
                    );
                    // Find the index of the content type byte
                    let content_type_index = match begin_zero {
                        Some(index) => index - 1,
                        None => app_data.len() - 16 - 1
                    };
    
                    // Process contents that are not handshakes differently
                    // Invalid: Raise an alert to remote side
                    // ChangeCipherSpec: It should not be encrypted, raise alert
                    // Alert: Reset TLS session and terminate TCP session directly
                    // Handshake: Normal procedure as below
                    // ApplicationData: Early data is silently ignored and wont be processed
                    match inner_content_type {
                        TlsContentType::Invalid | TlsContentType::ChangeCipherSpec => {
                            self.session.borrow_mut().invalidate_session(
                                AlertType::UnexpectedMessage,
                                &inner_plaintext[..content_type_index]
                            );
                            return Ok(propagated_poll);
                        },
                        TlsContentType::Alert => {
                            self.session.borrow_mut().reset_state();
                            return Ok(propagated_poll);
                        },
                        TlsContentType::ApplicationData => {
                            return Ok(propagated_poll);
                        },
                        _ => ()
                    }
    
                    let (_, mut inner_handshakes) = complete(
                        parse_inner_plaintext_for_handshake
                    )(inner_plaintext).unwrap();
    
                    // Sequentially process all handshakes
                    let num_of_handshakes = inner_handshakes.len();
                    for _ in 0..num_of_handshakes {
                        let (handshake_slice, handshake_repr) = inner_handshakes.remove(0);
                        if self.process(
                            handshake_slice,
                            TlsRepr {
                                content_type: TlsContentType::Handshake,
                                version: repr.version,
                                length: u16::try_from(handshake_repr.length).unwrap() + 4,
                                payload: None,
                                handshake: Some(handshake_repr)
                            }
                        ).is_err() {
                            return Ok(propagated_poll)
                        }
                    }
                },

                TlsContentType::ChangeCipherSpec |
                TlsContentType::Handshake => {
                    if self.process(repr_slice, repr).is_err() {
                        return Ok(propagated_poll)
                    }
                    log::info!("Processed record");
                },

                TlsContentType::Alert => {
                    self.session.borrow_mut().reset_state();
                    log::info!("Received alert, closing TCP socket..");
                },

                TlsContentType::Invalid => {
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        &repr.payload.unwrap_or(Vec::new())
                    );
                    log::info!("Received invalid TLS records, terminate immediately..");
                }
            }
        }

        Ok(propagated_poll)
    }

    // Process TLS ingress during handshake
    // The slice should ONLY include handshake overhead
    // i.e. Exclude 5 bytes of TLS Record
    //      Include 4 bytes of HandshakeRepr, everything within the same handshake
    fn process(&self, handshake_slice: &[u8], mut repr: TlsRepr) -> Result<()> {
        // Change_cipher_spec check:
        // Must receive CCS before recv peer's FINISH message
        // i.e. Must happen after START and before CONNECTED
        //
        // CCS message only exist for compatibility reason,
        // Drop the message and update `received_change_cipher_spec`
        // Note: CSS doesn't count as a proper record, no need to increment sequence number
        if repr.is_change_cipher_spec() {
            let mut session = self.session.try_borrow_mut().expect("Cannot borrow mut");
            session.receive_change_cipher_spec();
            return Ok(())
        }

        let tls_state = {
            self.session.borrow().get_tls_state()
        };
        match tls_state {
            // During WAIT_SH for a TLS client, client should wait for ServerHello
            TlsState::WAIT_SH => {
                if repr.is_server_hello() {
                    // Check SH content:
                    // random: Cannot represent HelloRequestRetry
                    // session_id_echo: should be same as the one sent by client
                    // cipher_suite: Store
                    //        (TODO: Check if such suite was offered)
                    // compression_method: Must be null, not supported in TLS 1.3
                    //
                    // Check extensions:
                    // supported_version: Must be TLS 1.3
                    // key_share: Store key, must be in secp256r1 or x25519

                    // "Cache" for ECDHE server public info
                    let mut p256_public: Option<EncodedPoint> = None;
                    let mut x25519_public: Option<x25519_dalek::PublicKey> = None;
                    let mut selected_cipher: Option<CipherSuite> = None;

                    // Process the handshake data within ServerHello
                    let handshake_data = &repr.handshake.as_ref().unwrap().handshake_data;
                    if let HandshakeData::ServerHello(server_hello) = handshake_data {

                        // Check random: Cannot be SHA-256 of "HelloRetryRequest"
                        if server_hello.random == HRR_RANDOM {
                            // Abort communication with illegal parameter alert
                            self.session.borrow_mut().invalidate_session(
                                AlertType::IllegalParameter,
                                handshake_slice
                            );
                            return Ok(());
                        }

                        // Check session_id_echo
                        // The socket should have a session_id after moving from START state
                        if !self.session.borrow().verify_session_id_echo(server_hello.session_id_echo) {
                            // Abort communication with illegal parameter alert
                            self.session.borrow_mut().invalidate_session(
                                AlertType::IllegalParameter,
                                handshake_slice
                            );
                            return Ok(());
                        }

                        // Note the selected cipher suite
                        selected_cipher.replace(server_hello.cipher_suite);

                        // TLSv13 forbidden key compression
                        if server_hello.compression_method != 0 {
                            // Abort communication with illegal parameter alert
                            self.session.borrow_mut().invalidate_session(
                                AlertType::IllegalParameter,
                                handshake_slice
                            );
                            return Ok(());
                        }

                        for extension in server_hello.extensions.iter() {
                            if extension.extension_type == ExtensionType::SupportedVersions {
                                if let ExtensionData::SupportedVersions(
                                    SupportedVersions::ServerHello {
                                        selected_version
                                    }
                                ) = extension.extension_data {
                                    if selected_version != TlsVersion::Tls13 {
                                        // Abort for choosing not offered TLS version,
                                        // with illegal parameter alert
                                        self.session.borrow_mut().invalidate_session(
                                            AlertType::IllegalParameter,
                                            handshake_slice
                                        );
                                        return Ok(());
                                    }
                                } else {
                                    // Abort for malformatted extension, with decode error alert
                                    self.session.borrow_mut().invalidate_session(
                                        AlertType::DecodeError,
                                        handshake_slice
                                    );
                                    return Ok(());
                                }
                            }

                            if extension.extension_type == ExtensionType::KeyShare {
                                if let ExtensionData::KeyShareEntry(
                                    KeyShareEntryContent::KeyShareServerHello {
                                        server_share
                                    }
                                ) = &extension.extension_data {
                                    match server_share.group {
                                        NamedGroup::secp256r1 => {
                                            p256_public.replace(
                                                EncodedPoint::from_untagged_bytes(
                                                    GenericArray::from_slice(&server_share.key_exchange[1..])
                                                )
                                            );
                                        },
                                        NamedGroup::x25519 => {
                                            let mut x25519_server_key: [u8; 32] = [0; 32];
                                            x25519_server_key.clone_from_slice(&server_share.key_exchange);
                                            x25519_public.replace(
                                                x25519_dalek::PublicKey::from(
                                                    x25519_server_key
                                                )
                                            );
                                        },
                                        // The client side implementation of this TLS socket only offers
                                        // P-256 and x25519 as ECDHE key exchange algorithms
                                        // Respond with illegal parameter alert and then terminate
                                        _ => {
                                            self.session.borrow_mut().invalidate_session(
                                                AlertType::IllegalParameter,
                                                handshake_slice
                                            );
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                        }

                    } else {
                        // Handle invalid TLS packet
                        self.session.borrow_mut().invalidate_session(
                            AlertType::DecodeError,
                            handshake_slice
                        );
                        return Ok(());
                    }

                    // Check that both selected_cipher and (p256_public OR x25519_public) were received
                    // The case where key_share extension exists but no appropriate keys are returned
                    // is considered in above. The only remaining case is that the `key share` entry extension
                    // is not sent at all.
                    if selected_cipher.is_none() || (p256_public.is_none() && x25519_public.is_none()) {
                        // Abort communication
                        self.session.borrow_mut().invalidate_session(
                            AlertType::MissingExtension,
                            handshake_slice
                        );
                        return Ok(());
                    }

                    // Get slice without reserialization
                    let mut session = self.session.borrow_mut();
                    session.client_update_for_sh(
                        selected_cipher.unwrap(),
                        p256_public,
                        x25519_public,
                        handshake_slice
                    );
                    // Key exchange occurred, seq_num is set to 0
                    // Do NOT update seq_num again. Early return.
                    return Ok(());
                }
            },

            // Expect encrypted extensions after receiving SH
            TlsState::WAIT_EE => {
                // Verify that it is indeed an EE
                let might_be_ee = repr.handshake.take().unwrap();
                if might_be_ee.get_msg_type() != HandshakeType::EncryptedExtensions {
                    // Unexpected message types
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        handshake_slice
                    );
                    return Ok(());
                }

                // Possiblity: Process payload
                // Practically, nothing will be done about cookies/server name
                // These fields are typically not session related
                // Extension processing is therefore skipped

                // Update hash of the session, get EE by taking appropriate length of data
                // Length of handshake header is 4
                let (_handshake_slice, ee_slice) = 
                    take::<_, _, (&[u8], ErrorKind)>(
                        might_be_ee.length + 4
                    )(handshake_slice)
                        .map_err(|_| Error::Unrecognized)?;

                self.session.borrow_mut()
                    .client_update_for_ee(
                        &ee_slice
                    );
                
                log::info!("Received EE");
           },

            // In this stage, wait for a certificate from server
            // Parse the certificate and check its content
            TlsState::WAIT_CERT_CR => {
                // Verify that it is indeed an Certificate, or CertificateRequest
                let might_be_cert = repr.handshake.take().unwrap();
                if might_be_cert.get_msg_type() == HandshakeType::Certificate {
                    // Process certificates

                    // let all_certificates = might_be_cert.get_all_asn1_der_certificates().unwrap();
                    // log::info!("Number of certificates: {:?}", all_certificates.len());
                    // log::info!("All certificates: {:?}", all_certificates);

                    // TODO: Process all certificates
                    let cert = might_be_cert.get_asn1_der_certificate().unwrap();

                    // TODO: Replace this block after implementing a proper 
                    // certificate verification procdeure
                    cert.validate_self_signed_signature().expect("Signature mismatched");

                    // Update session TLS state to WAIT_CV
                    // Length of handshake header is 4
                    let (_handshake_slice, cert_slice) = 
                        take::<_, _, (&[u8], ErrorKind)>(
                            might_be_cert.length + 4
                        )(handshake_slice)
                            .map_err(|_| Error::Unrecognized)?;

                    self.session.borrow_mut()
                        .client_update_for_wait_cert_cr(
                            &cert_slice,
                            cert.get_cert_public_key().unwrap()
                        );
                    log::info!("Received WAIT_CERT_CR");
                } else if might_be_cert.get_msg_type() == HandshakeType::CertificateRequest {
                    // Process signature algorithm extension
                    // Signature algorithm for the private key of client cert must be included
                    // within the list of signature algorithms
                    //
                    // Client is STRONGLY RECOMMENDED to use a signature algorithm within
                    // the list of `mandatory to implement` signature algorithms, including:
                    // rsa_pkcs1_sha256, rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256
                    //
                    // Update client state
                    let cert_req_extensions: &Vec<Extension> = might_be_cert
                        .get_cert_request_extensions()
                        .unwrap();
                    let sig_algs_ext: Option<&crate::tls_packet::Extension>
                        = cert_req_extensions
                            .iter()
                            .find( |&extension| {
                                extension.extension_type
                                    == crate::tls_packet::ExtensionType::SignatureAlgorithms
                                }
                            );
                    if sig_algs_ext.is_some() {
                        // Convert extension into SignatureScheme
                        if let crate::tls_packet::ExtensionData::SignatureAlgorithms(
                            scheme_list
                        ) = &sig_algs_ext.unwrap().extension_data {
                            // Update session TLS state to WAIT_CERT
                            // Length of handshake header is 4
                            let (_handshake_slice, cert_req_slice) = 
                                take::<_, _, (&[u8], ErrorKind)>(
                                    might_be_cert.length + 4
                                )(handshake_slice)
                                    .map_err(|_| Error::Unrecognized)?;
                            
                            self.session.borrow_mut()
                                .client_update_for_certificate_request(
                                    &cert_req_slice,
                                    &scheme_list.supported_signature_algorithms
                                );
                        }

                    } else {
                        // Reject connection, CertificateRequest must have
                        // SignatureAlgorithm extension
                        self.session.borrow_mut().invalidate_session(
                            AlertType::MissingExtension,
                            handshake_slice
                        );
                        return Ok(());
                    }
                    log::info!("Received WAIT_CERT_CR");
                } else {
                    // Throw alert for not recving certificate/certificate request from server side
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        handshake_slice
                    );
                    return Ok(());
                }
            },

            // In this stage, server will send a certificate chain
            // Verify the certificate
            TlsState::CLIENT_WAIT_CERT => {
                // Verify that it is indeed an Certificate
                let might_be_cert = repr.handshake.take().unwrap();

                if might_be_cert.get_msg_type() == HandshakeType::Certificate {
                    // Process certificates

                    // let all_certificates = might_be_cert.get_all_asn1_der_certificates().unwrap();
                    // log::info!("Number of certificates: {:?}", all_certificates.len());
                    // log::info!("All certificates: {:?}", all_certificates);

                    // TODO: Process all certificates
                    let cert = might_be_cert.get_asn1_der_certificate().unwrap();

                    // TODO: Replace this block after implementing a proper 
                    // certificate verification procdeure
                    cert.validate_self_signed_signature().expect("Signature mismatched");

                    // Update session TLS state to WAIT_CV
                    // Length of handshake header is 4
                    let (_handshake_slice, cert_slice) = 
                        take::<_, _, (&[u8], ErrorKind)>(
                            might_be_cert.length + 4
                        )(handshake_slice)
                            .map_err(|_| Error::Unrecognized)?;

                    self.session.borrow_mut()
                        .client_update_for_wait_cert_cr(
                            &cert_slice,
                            cert.get_cert_public_key().unwrap()
                        );
                    log::info!("Received WAIT_CERT");
                } else {
                    // Unexpected handshakes
                    // Throw alert
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        handshake_slice
                    );
                    return Ok(());
                }
            },

            // In this stage, server will eventually send a CertificateVerify
            // Verify that the signature is indeed correct
            TlsState::CLIENT_WAIT_CV => {
                // Ensure that it is CertificateVerify
                let might_be_cert_verify = repr.handshake.take().unwrap();
                if might_be_cert_verify.get_msg_type() != HandshakeType::CertificateVerify {
                    // Process the other handshakes in "handshake_vec"
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        handshake_slice
                    );
                    return Ok(());
                }

                // Take out the portion for CertificateVerify
                // Length of handshake header is 4
                let (_handshake_slice, cert_verify_slice) = 
                    take::<_, _, (&[u8], ErrorKind)>(
                        might_be_cert_verify.length + 4
                    )(handshake_slice)
                        .map_err(|_| Error::Unrecognized)?;

                // Perform verification, update TLS state if successful
                let (sig_alg, signature) = might_be_cert_verify.get_signature().unwrap();
                {
                    self.session.borrow_mut()
                        .client_update_for_wait_cv(
                            cert_verify_slice,
                            sig_alg,
                            signature
                        );
                }
                log::info!("Received CV");
            },

            // Client will receive a Finished handshake from server
            TlsState::CLIENT_WAIT_FINISHED => {
                // Ensure that it is Finished
                let might_be_server_finished = repr.handshake.take().unwrap();
                if might_be_server_finished.get_msg_type() != HandshakeType::Finished {
                    // Server Finished is expected.
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        handshake_slice
                    );
                    return Ok(());
                }

                // Take out the portion for server Finished
                // Length of handshake header is 4
                let (_handshake_slice, server_finished_slice) = 
                    take::<_, _, (&[u8], ErrorKind)>(
                        might_be_server_finished.length + 4
                    )(handshake_slice)
                        .map_err(|_| Error::Unrecognized)?;
                
                // Perform verification, update TLS state if successful
                // Update traffic secret, reset sequence number
                self.session.borrow_mut()
                    .client_update_for_wait_finished(
                        server_finished_slice,
                        might_be_server_finished.get_verify_data().unwrap()
                    );
                log::info!("Received server FIN");
            },

            // Server will reveice a Client Hello initiating the TLS handshake
            TlsState::SERVER_START => {
                // Ensure that is a Client Hello
                let might_be_client_hello = repr.handshake.take().unwrap();
                if might_be_client_hello.get_msg_type() != HandshakeType::ClientHello {
                    // Throw alert. Client Hello is expected.
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        handshake_slice
                    );
                    return Ok(());
                }

                // Process as Client Hello
                if let HandshakeData::ClientHello(client_hello)
                    = might_be_client_hello.handshake_data
                {
                    // Checks on the client hello structure
                    // Read session ID
                    // Select acceptable TLS 1.3 cipher suite
                    let session_id = client_hello.session_id;
                    let accepted_cipher_suite = {
                        let recognized_cipher_suite = client_hello.cipher_suites
                            .iter()
                            .find(|cipher_suite| {
                                // CCM_8 is the only unsupported cipher suite
                                if let Some(cipher) = cipher_suite {
                                    cipher != &CipherSuite::TLS_AES_128_CCM_8_SHA256
                                } else {
                                    false
                                }
                            });
                        if let Some(Some(nominated_cipher_suite)) = recognized_cipher_suite {
                            nominated_cipher_suite
                        } else {
                            // No appropriate cipher found,
                            // the full set of security measures cannot be set up.
                            // Send alert for this
                            self.session.borrow_mut().invalidate_session(
                                AlertType::HandshakeFailure,
                                handshake_slice
                            );
                            return Ok(());
                        }
                    };

                    // Check on the handshakes
                    // `supported_version` extension: only support TLS 1.3 (SSL 3.4)
                    // `supported_groups` extension: select an acceptable ECDHE group
                    // `key_share` extension: find the corresponding ECDHE shared key
                    // `signature_algorithm`: pick a signature algorithm
                    // Will not handle PSK, no 0-RTT
                    let mut offered_p256 = false;
                    let mut offered_x25519 = false;
                    let mut ecdhe_public_key: Option<DiffieHellmanPublicKey> = None;
                    let signature_algorithm: Option<SignatureScheme>;

                    // Verify that TLS 1.3 is offered by the client
                    if let Some(supported_version_extension) = client_hello.extensions.iter().find(
                        |extension| extension.extension_type == ExtensionType::SupportedVersions
                    ) {
                        if let ExtensionData::SupportedVersions(supported_version)
                            = &supported_version_extension.extension_data
                        {
                            if let SupportedVersions::ClientHello { versions, .. }
                                = supported_version
                            {
                                if versions.iter().find(
                                    |&&version| version == TlsVersion::Tls13
                                ).is_none()
                                {
                                    // TLS 1.3 was not offered by client
                                    // Reject connection immediately
                                    self.session.borrow_mut().invalidate_session(
                                        AlertType::IllegalParameter,
                                        handshake_slice
                                    );
                                    return Ok(());
                                }
                            } else {
                                // Wrong variant appeared, probably malformed
                                self.session.borrow_mut().invalidate_session(
                                    AlertType::DecodeError,
                                    handshake_slice
                                );
                                return Ok(());
                            }
                        } else {
                            // Malformed TLS packet
                            self.session.borrow_mut().invalidate_session(
                                AlertType::DecodeError,
                                handshake_slice
                            );
                            return Ok(());
                        }
                    } else {
                        // No supported_version extension was found,
                        // Terminate by sending alert
                        self.session.borrow_mut().invalidate_session(
                            AlertType::MissingExtension,
                            handshake_slice
                        );
                        return Ok(());
                    }

                    // Check offered ECDHE algorithm
                    if let Some(supported_groups) = client_hello.extensions.iter().find(
                        |extension| extension.extension_type == ExtensionType::SupportedGroups
                    ) {
                        if let ExtensionData::NegotiatedGroups(NamedGroupList { named_group_list, .. })
                            = &supported_groups.extension_data
                        {
                            // Mark down the offered and acceptable group
                            if let Some(_group) = named_group_list.iter().find(
                                |&&named_group| {
                                    named_group == NamedGroup::secp256r1
                                }
                            ) {
                                offered_p256 = true;
                            }

                            if let Some(_group) = named_group_list.iter().find(
                                |&&named_group| {
                                    named_group == NamedGroup::x25519
                                }
                            ) {
                                offered_x25519 = true;
                            }
                        } else {
                            // Malformed TLS packet
                            self.session.borrow_mut().invalidate_session(
                                AlertType::DecodeError,
                                handshake_slice
                            );
                            return Ok(());
                        }
                    } else {
                        // Client did not offer ECDHE algorithm within `supported version` extension
                        // While it is allowed, HRR is not handled as acceptable parameters
                        // should have been offered already initially.
                        // Possibility: Tolerate minor mismatch of client hello, and send HRR instead

                        self.session.borrow_mut().invalidate_session(
                            AlertType::MissingExtension,
                            handshake_slice
                        );
                        return Ok(());
                    }

                    // Select usable key
                    if let Some(key_shares) = client_hello.extensions.iter().find(
                        |extension| extension.extension_type == ExtensionType::KeyShare
                    ) {
                        if let ExtensionData::KeyShareEntry(
                            KeyShareEntryContent::KeyShareClientHello { client_shares, .. }
                        ) = &key_shares.extension_data {
                            // Try P-256 first, if offered by client
                            if offered_p256 {
                                if let Some(p256_key) = client_shares.iter().find(
                                    |key| {
                                        key.group == NamedGroup::secp256r1
                                    }
                                ) {
                                    ecdhe_public_key.replace(
                                        DiffieHellmanPublicKey::SECP256R1 {
                                            encoded_point: p256::EncodedPoint::from_untagged_bytes(
                                                GenericArray::from_slice(
                                                    &p256_key.key_exchange[1..]
                                                )
                                            )
                                        }
                                    );
                                }
                            }

                            // Then try X25519, if P-256 key is not found and x25519 is offered
                            if offered_x25519 && ecdhe_public_key.is_none() {
                                if let Some(x25519_key) = client_shares.iter().find(
                                    |key| {
                                        key.group == NamedGroup::x25519
                                    }
                                ) {
                                    // Prepare a 32-bytes buffer for the public key
                                    let mut key_content: [u8; 32] = [0; 32];

                                    key_content.clone_from_slice(&x25519_key.key_exchange);
                                    ecdhe_public_key.replace(
                                        DiffieHellmanPublicKey::X25519 {
                                            public_key: x25519_dalek::PublicKey::from(
                                                key_content
                                            )
                                        }
                                    );
                                }
                            }

                            // There are no applicable offered client key,
                            // Proper way of handling: Send a HelloRetryRequest with key generated
                            if ecdhe_public_key.is_none() {
                                self.session.borrow_mut().invalidate_session(
                                    AlertType::HandshakeFailure,
                                    handshake_slice
                                );
                                return Ok(());
                            }
                        } else {
                            // Malformed packet
                            // Send alert to client
                            self.session.borrow_mut().invalidate_session(
                                AlertType::DecodeError,
                                handshake_slice
                            );
                            return Ok(());
                        }
                    } else {
                        // The key_share extension was not sent
                        // Proper way of handling: Send a HelloRetryRequest with key generated
                        self.session.borrow_mut().invalidate_session(
                            AlertType::MissingExtension,
                            handshake_slice
                        );
                        return Ok(());
                    }

                    // Select signature algorithm
                    if let Some(signature_algorithms) = client_hello.extensions.iter().find(
                        |extension| extension.extension_type == ExtensionType::SignatureAlgorithms
                    ) {
                        if let ExtensionData::SignatureAlgorithms(
                            SignatureSchemeList { supported_signature_algorithms, .. }
                        ) = &signature_algorithms.extension_data {
                            // Check compatibility of signature algorithms
                            if let Some(certificate_private_key) = self.session.borrow().get_certificate_private_key() {
                                use crate::session::CertificatePrivateKey::*;
                                if let Some(server_signature_algorithm) = match certificate_private_key {
                                    // Try RSA keys:
                                    RSA { .. } => {
                                        supported_signature_algorithms.iter().find(
                                            |&&signature_algorithm| {
                                                signature_algorithm == SignatureScheme::rsa_pkcs1_sha256 ||
                                                    signature_algorithm == SignatureScheme::rsa_pkcs1_sha384 ||
                                                    signature_algorithm == SignatureScheme::rsa_pkcs1_sha512 ||
                                                    signature_algorithm == SignatureScheme::rsa_pss_rsae_sha256 ||
                                                    signature_algorithm == SignatureScheme::rsa_pss_rsae_sha384 ||
                                                    signature_algorithm == SignatureScheme::rsa_pss_rsae_sha512 ||
                                                    signature_algorithm == SignatureScheme::rsa_pss_pss_sha256 ||
                                                    signature_algorithm == SignatureScheme::rsa_pss_pss_sha384 ||
                                                    signature_algorithm == SignatureScheme::rsa_pss_pss_sha512
                                            }
                                        )
                                    },
                                    ECDSA_SECP256R1_SHA256 { .. } => {
                                        supported_signature_algorithms.iter().find(
                                            |&&signature_algorithm| {
                                                signature_algorithm == SignatureScheme::ecdsa_secp256r1_sha256
                                            }
                                        )
                                    },
                                    ED25519 { .. } => {
                                        supported_signature_algorithms.iter().find(
                                            |&&signature_algorithm| {
                                                signature_algorithm == SignatureScheme::ed25519
                                            }
                                        )
                                    }
                                } {
                                    signature_algorithm = Some(*server_signature_algorithm);
                                } else {
                                    // Cannot find a suitable signature algorithm for the server side
                                    // Terminate the negotiation with an alert
                                    self.session.borrow_mut().invalidate_session(
                                        AlertType::HandshakeFailure,
                                        handshake_slice
                                    );
                                    return Ok(());
                                }

                            } else {
                                // Server must have a certificate ready
                                // Through this should be enforced when entering listening stage
                                unreachable!()
                            }
                        } else {
                            // Malformed packet, type does not match content
                            self.session.borrow_mut().invalidate_session(
                                AlertType::DecodeError,
                                handshake_slice
                            );
                            return Ok(());
                        }
                    } else {
                        // Will only accept authentication through certificate
                        // Send alert if there are no signature algorithms extension
                        self.session.borrow_mut().invalidate_session(
                            AlertType::MissingExtension,
                            handshake_slice
                        );
                        return Ok(());
                    }

                    {
                        let mut session = self.session.borrow_mut();
                        session.server_update_for_begin(
                            *accepted_cipher_suite,
                            ecdhe_public_key.unwrap(),
                            session_id,
                            signature_algorithm.unwrap(),
                            handshake_slice
                        )
                    }

                    log::info!("Processed client hello")
                }
            },

            TlsState::SERVER_WAIT_FINISHED => {
                // Ensure that it is Finished
                let might_be_client_finished = repr.handshake.take().unwrap();
                if might_be_client_finished.get_msg_type() != HandshakeType::Finished {
                    // Expected to recv client finished
                    self.session.borrow_mut().invalidate_session(
                        AlertType::UnexpectedMessage,
                        handshake_slice
                    );
                    return Ok(());
                }

                // Take out the portion for server Finished
                // Length of handshake header is 4
                let (_handshake_slice, client_finished_slice) = 
                    take::<_, _, (&[u8], ErrorKind)>(
                        might_be_client_finished.length + 4
                    )(handshake_slice)
                        .map_err(|_| Error::Unrecognized)?;
                
                // Perform verification, update TLS state if successful
                // Update traffic secret, reset sequence number
                self.session.borrow_mut()
                    .server_update_for_wait_finished(
                        client_finished_slice,
                        might_be_client_finished.get_verify_data().unwrap()
                    );
                log::info!("Received client FIN");
            }

            _ => {},
        }
        Ok(())
    }

    // Send method for TLS Handshake that needs to be encrypted.
    // Does the following things:
    // 1. Encryption
    // 2. Add TLS header in front of application data
    // Input should be inner plaintext
    // Note: Do not put this slice into the transcript hash. It is polluted.
    // TODO: Rename this function. It is only good for client finished
    fn send_application_slice(&mut self, slice: &mut [u8]) -> Result<()> {
        let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_send() {
            return Err(Error::Illegal);
        }
        // Borrow session in advance
        let mut session = self.session.borrow_mut();

        // Pre-compute TLS record layer as associated_data
        let mut associated_data: [u8; 5] = [0x17, 0x03, 0x03, 0x00, 0x00];
        let auth_tag_length: u16 = match session.get_cipher_suite_type() {
            Some(CipherSuite::TLS_AES_128_GCM_SHA256) |
            Some(CipherSuite::TLS_AES_256_GCM_SHA384) |
            Some(CipherSuite::TLS_AES_128_CCM_SHA256) |
            Some(CipherSuite::TLS_CHACHA20_POLY1305_SHA256) => {
                16
            },
            _ => return Err(Error::Illegal),
        };

        NetworkEndian::write_u16(
            &mut associated_data[3..5],
            auth_tag_length + u16::try_from(slice.len()).unwrap()
        );

        let auth_tag = session.encrypt_in_place_detached(
            &associated_data,
            slice
        ).map_err(|_| Error::Illegal)?;

        tcp_socket.send_slice(&associated_data)?;
        tcp_socket.send_slice(&slice)?;
        tcp_socket.send_slice(&auth_tag)?;

        session.increment_local_sequence_number();
        Ok(())
    }

    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_recv() {
            return Ok(0);
        }

        let mut session = self.session.borrow_mut();

        // If the handshake is not completed, do not pull bytes out of the buffer
        // through TlsSocket.recv_slice()
        // Handshake recv should be through TCPSocket directly.
        if session.get_tls_state() != TlsState::CLIENT_CONNECTED &&
            session.get_tls_state() != TlsState::SERVER_CONNECTED {
            return Ok(0);
        }

        let (recv_slice_size, acceptable) = tcp_socket.recv(
            |buffer| {
                // Read the size of the TLS record beforehand
                let record_length: usize = NetworkEndian::read_u16(&buffer[3..5]).into();
                let provided_data_capacity: usize = data.len();
                // Copy the entire byte representation of TLS packet into the
                // user-provided buffer, if possible
                if provided_data_capacity >= (record_length + 5) {
                    &data[..(record_length + 5)].clone_from_slice(&buffer[..(record_length + 5)]);
                }
                (
                    (record_length + 5),
                    (
                        (record_length + 5),
                        provided_data_capacity >= (record_length + 5)
                    )
                )
            }
        )?;

        if !acceptable {
            return Ok(0);
        }

        // Encrypted data need a TLS record wrapper (5 bytes)
        // Authentication tag (16 bytes, for all supported AEADs)
        // Content type byte (1 byte)
        // Zero paddings (>=0 bytes)
        if recv_slice_size < 22 {
            return Ok(0);
        }
        
        // Get Associated Data
        let mut associated_data: [u8; 5] = [0; 5];
        associated_data.clone_from_slice(&data[..5]);

        // Dump association data (TLS Record wrapper)
        // Only decrypt application data
        // Always increment sequence number after decrpytion
        log::info!("Sequence number: {:?}", session.server_sequence_number);
        session.decrypt_application_data_in_place(
            &associated_data,
            &mut data[5..recv_slice_size]
        ).unwrap();
        session.increment_remote_sequence_number();

        // Make sure it is application data
        let (content_type, padding_start_index) =
            get_content_type_inner_plaintext(&data[..(recv_slice_size-16)]);

        // If it is not application data, handle it internally
        if content_type != TlsContentType::ApplicationData {
            // TODO: Implement key update here, as it could be a key update
            log::info!("Other decrypted: {:?}", &data[..(recv_slice_size-16)]);
            return Ok(0);
        }

        // Otherwise, it is surely application data.
        // Prune TLS record wrapper (5 bytes) from data.
        data.rotate_left(5);
        
        // Remove extra length:
        // 5 bytes of TLS record header
        // 16 bytes of authentication tag (included in zero padding search fn)
        // 1 byte of content type
        // zero paddings, variated length
        let actual_application_data_length = recv_slice_size - 5 - 1
            - padding_start_index.map_or(16,
                |start| recv_slice_size - start
            );

        Ok(actual_application_data_length)
    }

    pub fn send_slice(&mut self, data: &[u8]) -> Result<usize> {
        // If the handshake is not completed, do not push bytes onto the buffer
        // through TlsSocket.send_slice()
        // Handshake send should be through TCPSocket directly.
        let mut session = self.session.borrow_mut();
        if session.get_tls_state() != TlsState::CLIENT_CONNECTED &&
            session.get_tls_state() != TlsState::SERVER_CONNECTED {
            return Ok(0);
        }
        let data_length = data.len();

        // Sending order:
        // 1. Associated data/ TLS Record layer
        // 2. Encrypted { Payload (data) | Content type: Application Data }
        // 3. Authentication tag (16 bytes for all supported AEADs)
        let mut associated_data: [u8; 5] = [
            0x17,           // Application data
            0x03, 0x03,     // TLS 1.3 record disguised as TLS 1.2
            0x00, 0x00      // Length of encrypted data, yet to be determined
        ];

        NetworkEndian::write_u16(&mut associated_data[3..5],
            u16::try_from(data_length).unwrap()  // Payload length
            + 1                                 // Content type length
            + 16                                // Auth tag length
        );

        let mut vec: HeaplessVec<u8, U1024> = HeaplessVec::from_slice(data).unwrap();
        vec.push(0x17).unwrap();                // Content type
        
        let tag = session.encrypt_application_data_in_place_detached(
            &associated_data,
            &mut vec
        ).unwrap();
        session.increment_local_sequence_number();

        let mut tcp_socket = self.sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_send() {
            return Err(Error::Illegal);
        }

        tcp_socket.send_slice(&associated_data)?;
        tcp_socket.send_slice(&vec)?;
        tcp_socket.send_slice(&tag)?;

        Ok(data_length)
    }

    pub fn is_connected(&self) -> Result<bool> {
        let session = self.session.borrow();
        Ok(
            session.get_tls_state() == TlsState::CLIENT_CONNECTED ||
            session.get_tls_state() == TlsState::SERVER_CONNECTED            
        )
    }

    // Send `Close notify` alert to remote side
    // Set state to `CLOSED`
    // Leave TCP termination to polling method
    pub fn close(&mut self) -> Result<()> {
        let mut session = self.session.borrow_mut();
        match session.get_tls_state() {
            // Send a `close notify` if handshake is established
            TlsState::CLIENT_CONNECTED | TlsState::SERVER_CONNECTED => {
                session.invalidate_session(
                    AlertType::CloseNotify,
                    &[]
                );
            },
            // Do nothing if handshake hasn't even started
            TlsState::DEFAULT => {},
            // Send `user cancaled` to cancel the handshake negotiation
            // if it is currently in the middle of one
            _ => {
                session.invalidate_session(
                    AlertType::UserCanceled,
                    &[]
                );
            }
        }

        Ok(())
    }
}

use core::fmt;
impl<'a, 'b, 'c> fmt::Write for TlsSocket<'a, 'b, 'c> {
    fn write_str(&mut self, slice: &str) -> fmt::Result {
        let slice = slice.as_bytes();
        if self.send_slice(slice) == Ok(slice.len()) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}
