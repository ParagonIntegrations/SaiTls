use smoltcp::socket::TcpSocket;
use smoltcp::socket::TcpState;
use smoltcp::socket::Socket;
use smoltcp::socket::AnySocket;
use smoltcp::socket::SocketRef;
use smoltcp::socket::SocketHandle;
use smoltcp::socket::SocketSet;
use smoltcp::socket::TcpSocketBuffer;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::IpEndpoint;
use smoltcp::Result;
use smoltcp::Error;
use smoltcp::iface::EthernetInterface;
use smoltcp::time::Instant;
use smoltcp::phy::Device;

use byteorder::{ByteOrder, NetworkEndian, BigEndian};
use generic_array::GenericArray;

use core::convert::TryInto;
use core::convert::TryFrom;
use core::cell::RefCell;

use rand_core::{RngCore, CryptoRng};
use p256::{EncodedPoint, AffinePoint, ecdh::EphemeralSecret, ecdh::SharedSecret};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use ccm::{Ccm, consts::*};
use aes_gcm::aes::Aes128;
use aes_gcm::{AeadInPlace, NewAead};
use sha2::{Sha256, Sha384, Sha512, Digest};

use nom::bytes::complete::take;
use nom::IResult;
use nom::error::make_error;
use nom::error::ErrorKind;

use alloc::vec::{ self, Vec };
use heapless::Vec as HeaplessVec;

use crate::Error as TlsError;
use crate::tls_packet::*;
use crate::parse::{
    parse_tls_repr,
    parse_handshake,
    parse_inner_plaintext_for_handshake,
    get_content_type_inner_plaintext
};
use crate::buffer::TlsBuffer;
use crate::session::{Session, TlsRole};
use crate::certificate::validate_root_certificate;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub(crate) enum TlsState {
    START,
    WAIT_SH,
    WAIT_EE,
    WAIT_CERT_CR,
    WAIT_CERT,
    WAIT_CV,
    WAIT_FINISHED,
    SERVER_CONNECTED,   // Additional state, for client to send Finished after server Finished
    CONNECTED,
}

// TODO: Group up all session_specific parameters into a separate structure
pub struct TlsSocket<R: 'static + RngCore + CryptoRng>
{
    tcp_handle: SocketHandle,
    rng: R,
    session: RefCell<Session>,
}

impl<R: 'static + RngCore + CryptoRng> TlsSocket<R> {
    pub fn new<'a, 'b, 'c>(
        sockets: &mut SocketSet<'a, 'b, 'c>,
        rx_buffer: TcpSocketBuffer<'b>,
        tx_buffer: TcpSocketBuffer<'b>,
        rng: R,
    ) -> Self
    where
        'b: 'c,
    {
        let tcp_socket = TcpSocket::new(rx_buffer, tx_buffer);
        let tcp_handle = sockets.add(tcp_socket);
        TlsSocket {
            tcp_handle,
            rng,
            session: RefCell::new(
                Session::new(TlsRole::Client)
            ),
        }
    }

    pub fn tcp_connect<T, U>(
        &mut self,
        sockets: &mut SocketSet,
        remote_endpoint: T,
        local_endpoint: U,
    ) -> Result<()>
    where
        T: Into<IpEndpoint>,
        U: Into<IpEndpoint>,
    {
        let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
        if tcp_socket.state() == TcpState::Established {
            Ok(())
        } else {
            tcp_socket.connect(remote_endpoint, local_endpoint)
        }
    }

    pub fn tls_connect<DeviceT>(
        &mut self,
        iface: &mut EthernetInterface<DeviceT>,
        sockets: &mut SocketSet,
        now: Instant
    ) -> Result<bool>
    where
        DeviceT: for<'d> Device<'d>
    {
        // Check tcp_socket connectivity
        {
            let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
            tcp_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(1000)));
            if tcp_socket.state() != TcpState::Established {
                return Ok(false);
            }
        }

        // Handle TLS handshake through TLS states
        let tls_state = {
            self.session.borrow().get_tls_state()
        };
        match tls_state {
            // Initiate TLS handshake
            TlsState::START => {
                // Prepare field that is randomised,
                // Supply it to the TLS repr builder.
                let ecdh_secret = EphemeralSecret::random(&mut self.rng);
                let mut random: [u8; 32] = [0; 32];
                let mut session_id: [u8; 32] = [0; 32];
                self.rng.fill_bytes(&mut random);
                self.rng.fill_bytes(&mut session_id);
                let repr = TlsRepr::new()
                    .client_hello(&ecdh_secret, random, session_id.clone());

                // Update hash function with client hello handshake
                let mut array = [0; 512];
                let mut buffer = TlsBuffer::new(&mut array);
                buffer.enqueue_tls_repr(repr)?;
                let slice: &[u8] = buffer.into();

                // Send the packet
                self.send_tls_slice(sockets, slice)?;

                // Update TLS session
                self.session.borrow_mut().client_update_for_ch(
                    ecdh_secret,
                    session_id,
                    &slice[5..]
                );
            },

            // TLS Client wait for Server Hello
            // No need to send anything
            TlsState::WAIT_SH => {},

            // TLS Client wait for certificate from TLS server
            // No need to send anything
            // Note: TLS server should normally send SH alongside EE
            // TLS client should jump from WAIT_SH directly to WAIT_CERT_CR directly.
            TlsState::WAIT_EE => {},

            // TLS Client wait for server's certificate
            // No need to send anything
            TlsState::WAIT_CERT_CR => {},

            // TLS Client wait for server's certificate cerify
            // No need to send anything
            TlsState::WAIT_CV => {},

            // Last step of server authentication
            // TLS Client wait for server's Finished handshake
            // No need to send anything
            TlsState::WAIT_FINISHED => {}

            // Send client Finished to end handshake
            TlsState::SERVER_CONNECTED => {
                let mut inner_plaintext: HeaplessVec<u8, U64> = {
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
                self.send_application_slice(sockets, &mut inner_plaintext.clone())?;
                self.session.borrow_mut()
                    .client_update_for_server_connected(&inner_plaintext);
            }

            _ => todo!()
        }

        // Poll the network interface
        iface.poll(sockets, now);

        // Read for TLS packet
        let mut array: [u8; 2048] = [0; 2048];
        let mut tls_repr_vec = self.recv_tls_repr(sockets, &mut array)?;

        // Take the TLS representation out of the vector,
        // Process as a queue
        let tls_repr_vec_size = tls_repr_vec.len();
        for index in 0..tls_repr_vec_size {
            let repr = tls_repr_vec.remove(0);
            self.process(repr)?;
        }

        Ok(self.session.borrow().has_completed_handshake())
    }

    // Process TLS ingress during handshake
    fn process(&self, mut repr: TlsRepr) -> Result<()> {
        // Change_cipher_spec check:
        // Must receive CCS before recv peer's FINISH message
        // i.e. Must happen after START and before CONNECTED
        //
        // CCS message only exist for compatibility reason,
        // Drop the message and update `received_change_cipher_spec`
        // Note: CSS doesn't count as a proper record, no need to increment sequence number
        if repr.is_change_cipher_spec() {
            let mut session = self.session.borrow_mut();
            session.receive_change_cipher_spec();
            return Ok(())
        }

        let tls_state = {
            self.session.borrow().get_tls_state()
        };
        match tls_state {
            // During WAIT_SH for a TLS client, client should wait for ServerHello
            TlsState::WAIT_SH => {
                // Legacy_protocol must be TLS 1.2
                if repr.version != TlsVersion::Tls12 {
                    // Abort communication
                    todo!()
                }

                // TODO: Validate SH
                if repr.is_server_hello() {
                    // Check SH content:
                    // random: Cannot represent HelloRequestRetry
                    //        (TODO: Support other key shares, e.g. X25519)
                    // session_id_echo: should be same as the one sent by client
                    // cipher_suite: Store
                    //        (TODO: Check if such suite was offered)
                    // compression_method: Must be null, not supported in TLS 1.3
                    //
                    // Check extensions:
                    // supported_version: Must be TLS 1.3
                    // key_share: Store key, must be in secp256r1
                    //        (TODO: Support other key shares ^)

                    // "Cache" for ECDHE server public info
                    let mut server_public: Option<EncodedPoint> = None;
                    let mut selected_cipher: Option<CipherSuite> = None;

                    // Process the handshake data within ServerHello
                    let handshake_data = &repr.handshake.as_ref().unwrap().handshake_data;
                    if let HandshakeData::ServerHello(server_hello) = handshake_data {

                        // Check random: Cannot be SHA-256 of "HelloRetryRequest"
                        if server_hello.random == HRR_RANDOM {
                            // Abort communication
                            todo!()
                        }

                        // Check session_id_echo
                        // The socket should have a session_id after moving from START state
                        if !self.session.borrow().verify_session_id_echo(server_hello.session_id_echo) {
                            // Abort communication
                            todo!()
                        }

                        // Note the selected cipher suite
                        selected_cipher.replace(server_hello.cipher_suite);

                        // TLSv13 forbidden key compression
                        if server_hello.compression_method != 0 {
                            // Abort communciation
                            todo!()
                        }

                        for extension in server_hello.extensions.iter() {
                            if extension.extension_type == ExtensionType::SupportedVersions {
                                if let ExtensionData::SupportedVersions(
                                    SupportedVersions::ServerHello {
                                        selected_version
                                    }
                                ) = extension.extension_data {
                                    if selected_version != TlsVersion::Tls13 {
                                        // Abort for choosing not offered TLS version
                                        todo!()
                                    }
                                } else {
                                    // Abort for illegal extension
                                    todo!()
                                }
                            }

                            if extension.extension_type == ExtensionType::KeyShare {
                                if let ExtensionData::KeyShareEntry(
                                    KeyShareEntryContent::KeyShareServerHello {
                                        server_share
                                    }
                                ) = &extension.extension_data {
                                    // TODO: Use legitimate checking to ensure the chosen
                                    // group is indeed acceptable, when allowing more (EC)DHE
                                    // key sharing
                                    if server_share.group != NamedGroup::secp256r1 {
                                        // Abort for wrong key sharing
                                        todo!()
                                    }
                                    // Store key
                                    // It is surely from secp256r1, no other groups are permitted
                                    // Convert untagged bytes into encoded point on p256 eliptic curve
                                    // Slice the first byte out of the bytes
                                    server_public.replace(
                                        EncodedPoint::from_untagged_bytes(
                                            GenericArray::from_slice(&server_share.key_exchange[1..])
                                        )
                                    );
                                }
                            }
                        }

                    } else {
                        // Handle invalid TLS packet
                        todo!()
                    }

                    // Check that both selected_cipher and server_public were received
                    if selected_cipher.is_none() || server_public.is_none() {
                        // Abort communication
                        todo!()
                    }

                    // This is indeed a desirable ServerHello TLS repr
                    // Reprocess ServerHello into a slice
                    // Update session with required parameter
                    let mut array = [0; 512];
                    let mut buffer = TlsBuffer::new(&mut array);
                    buffer.enqueue_tls_repr(repr)?;
                    let slice: &[u8] = buffer.into();
                    let mut session = self.session.borrow_mut();
                    session.client_update_for_sh(
                        selected_cipher.unwrap(),
                        server_public.unwrap(),
                        &slice[5..]
                    );
                    // Key exchange occurred, seq_num is set to 0
                    // Do NOT update seq_num again. Early return.
                    return Ok(());
                }
            },

            // Expect encrypted extensions after receiving SH
            TlsState::WAIT_EE => {
                // Check that the packet is classified as application data
                if !repr.is_application_data() {
                    // Abort communication, this affect IV calculation
                    todo!()
                }

                // ExcepytedExtensions are disguised as ApplicationData
                // Pull out the `payload` from TlsRepr, decrypt as EE
                let mut payload = repr.payload.take().unwrap();
                let mut array: [u8; 5] = [0; 5];
                let mut buffer = TlsBuffer::new(&mut array);
                buffer.write_u8(repr.content_type.into())?;
                buffer.write_u16(repr.version.into())?;
                buffer.write_u16(repr.length)?;
                let associated_data: &[u8] = buffer.into();
                {
                    self.session.borrow_mut().decrypt_in_place(
                        associated_data,
                        &mut payload
                    );
                }

                let parse_result = parse_inner_plaintext_for_handshake(&payload);
                let (_, (mut handshake_slice, mut handshake_vec)) = 
                    parse_result.map_err(|_| Error::Unrecognized)?;

                // Verify that it is indeed an EE
                let might_be_ee = handshake_vec.remove(0);
                if might_be_ee.get_msg_type() != HandshakeType::EncryptedExtensions {
                    // Process the other handshakes in "handshake_vec"
                    todo!()
                }

                // TODO: Process payload

                // Practically, nothing will be done about cookies/server name
                // Extension processing is therefore skipped
                // Update hash of the session, get EE by taking appropriate length of data
                // Length of handshake header is 4
                let (handshake_slice, ee_slice) = 
                    take::<_, _, (&[u8], ErrorKind)>(
                        might_be_ee.length + 4
                    )(handshake_slice)
                        .map_err(|_| Error::Unrecognized)?;

                self.session.borrow_mut()
                    .client_update_for_ee(
                        &ee_slice
                    );

                // TODO: Handle in WAIT_CERT_CR if there are still unprocessed handshakes
                // Ideas: 1. Split off WAIT_CERT_CR handling into a separate function
                //              so WAIT_EE branch can jsut call WAIT_CERT_CR branch
                //              if there are extra handshake unprocessed
                // 2. Merge state dependent listeners into 1 branch, execute conditionally
            },

            // In this stage, wait for a certificate from server
            // Parse the certificate and check its content
            TlsState::WAIT_CERT_CR => {
                // Check that the packet is classified as application data
                // Certificates transfer is disguised as application data
                if !repr.is_application_data() {
                    // Abort communication, this affect IV calculation
                    todo!()
                }

                // Pull out the `payload` from TlsRepr, decrypt as CERT
                let mut payload = repr.payload.take().unwrap();

                // Instantiate associated data and decrypt
                let mut array: [u8; 5] = [0; 5];
                let mut buffer = TlsBuffer::new(&mut array);
                buffer.write_u8(repr.content_type.into())?;
                buffer.write_u16(repr.version.into())?;
                buffer.write_u16(repr.length)?;
                let associated_data: &[u8] = buffer.into();
                {
                    self.session.borrow_mut().decrypt_in_place(
                        associated_data,
                        &mut payload
                    );
                }

                // Parse the certificate from TLS payload
                let parse_result = parse_inner_plaintext_for_handshake(&payload);
                let (_, (handshake_slice, mut handshake_vec)) = parse_result
                    .map_err(|_| Error::Unrecognized)?;

                // Verify that it is indeed an Certificate
                let might_be_cert = handshake_vec.remove(0);
                if might_be_cert.get_msg_type() != HandshakeType::Certificate {
                    // Process the other handshakes in "handshake_vec"
                    todo!()
                }

                // TODO: Process Certificate
                let cert = might_be_cert.get_asn1_der_certificate().unwrap();

                // TODO: Replace this block after implementing a proper 
                // certificate verification procdeure
                match validate_root_certificate(cert) {
                    Ok(true) => {},
                    _ => panic!("Certificate does not match")
                }

                // Update session TLS state to WAIT_CV
                // Length of handshake header is 4
                let (handshake_slice, cert_slice) = 
                    take::<_, _, (&[u8], ErrorKind)>(
                        might_be_cert.length + 4
                    )(handshake_slice)
                        .map_err(|_| Error::Unrecognized)?;

                self.session.borrow_mut()
                    .client_update_for_wait_cert_cr(
                        &cert_slice,
                        cert.return_rsa_public_key().unwrap()
                    );
            },

            // In this stage, server will eventually send a CertificateVerify
            // Verify that the signature is indeed correct
            TlsState::WAIT_CV => {
                // CertificateVerify is disguised as Application Data
                if !repr.is_application_data() {
                    // Abort communication, this affect IV calculation
                    todo!()
                }

                // Pull out the `payload` from TlsRepr, decrypt as CV
                let mut payload = repr.payload.take().unwrap();

                // Instantiate associated data and decrypt
                let mut array: [u8; 5] = [0; 5];
                let mut buffer = TlsBuffer::new(&mut array);
                buffer.write_u8(repr.content_type.into())?;
                buffer.write_u16(repr.version.into())?;
                buffer.write_u16(repr.length)?;
                let associated_data: &[u8] = buffer.into();
                {
                    self.session.borrow_mut().decrypt_in_place(
                        associated_data,
                        &mut payload
                    );
                }

                // Parse the certificate from TLS payload
                let parse_result = parse_inner_plaintext_for_handshake(&payload);
                let (_, (handshake_slice, mut handshake_vec)) = parse_result
                    .map_err(|_| Error::Unrecognized)?;

                // Ensure that it is CertificateVerify
                let might_be_cert_verify = handshake_vec.remove(0);
                if might_be_cert_verify.get_msg_type() != HandshakeType::CertificateVerify {
                    // Process the other handshakes in "handshake_vec"
                    todo!()
                }

                // Take out the portion for CertificateVerify
                // Length of handshake header is 4
                let (handshake_slice, cert_verify_slice) = 
                    take::<_, _, (&[u8], ErrorKind)>(
                        might_be_cert_verify.length + 4
                    )(handshake_slice)
                        .map_err(|_| Error::Unrecognized)?;

                // Perform verification, update TLS state if successful
                let (sig_alg, signature) = might_be_cert_verify.get_signature().unwrap();
                self.session.borrow_mut()
                    .client_update_for_wait_cv(
                        cert_verify_slice,
                        sig_alg,
                        signature
                    );
            },

            // Client will receive a Finished handshake from server
            TlsState::WAIT_FINISHED => {
                // Finished is disguised as Application Data
                if !repr.is_application_data() {
                    // Abort communication, this affect IV calculation
                    todo!()
                }

                // Pull out the `payload` from TlsRepr, decrypt as Finished
                let mut payload = repr.payload.take().unwrap();

                // Instantiate associated data and decrypt
                let mut array: [u8; 5] = [0; 5];
                let mut buffer = TlsBuffer::new(&mut array);
                buffer.write_u8(repr.content_type.into())?;
                buffer.write_u16(repr.version.into())?;
                buffer.write_u16(repr.length)?;
                let associated_data: &[u8] = buffer.into();
                {
                    self.session.borrow_mut().decrypt_in_place(
                        associated_data,
                        &mut payload
                    );
                }

                // Parse the TLS inner ciphertext as a Finished handshake
                let parse_result = parse_inner_plaintext_for_handshake(&payload);
                let (_, (handshake_slice, mut handshake_vec)) = parse_result
                    .map_err(|_| Error::Unrecognized)?;

                // Ensure that it is Finished
                let might_be_server_finished = handshake_vec.remove(0);
                if might_be_server_finished.get_msg_type() != HandshakeType::Finished {
                    // Process the other handshakes in "handshake_vec"
                    todo!()
                }

                // Take out the portion for server Finished
                // Length of handshake header is 4
                let (handshake_slice, server_finished_slice) = 
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
            }

            _ => {},
        }

        // A TLS Record was received and processed and verified
        // Increment sequence number
        self.session.borrow_mut().increment_server_sequence_number();

        Ok(())
    }

    // Generic inner send method, through TCP socket
    fn send_tls_repr(&self, sockets: &mut SocketSet, tls_repr: TlsRepr) -> Result<()> {
        let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_send() {
            return Err(Error::Illegal);
        }
        let mut array = [0; 2048];
        let mut buffer = TlsBuffer::new(&mut array);
        buffer.enqueue_tls_repr(tls_repr)?;
        let buffer_size = buffer.get_size();

        // Force send to return if send is unsuccessful
        // Only update sequence number if the send is successful
        tcp_socket.send_slice(buffer.into())
            .and_then(
                |size| if size == buffer_size {
                    Ok(())
                } else {
                    Err(Error::Truncated)
                }
            )?;
        self.session.borrow_mut().increment_client_sequence_number();
        Ok(())
    }

    // Generic inner send method for buffer IO, through TCP socket
    // Usage: Push a slice representation of ONE TLS packet
    // This function will only increment sequence number by 1
    // Repeatedly call this function if sending multiple TLS packets is needed
    fn send_tls_slice(&self, sockets: &mut SocketSet, slice: &[u8]) -> Result<()> {
        let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_send() {
            return Err(Error::Illegal);
        }
        let buffer_size = slice.len();
        tcp_socket.send_slice(slice)
            .and_then(
                |size| if size == buffer_size {
                    Ok(())
                } else {
                    Err(Error::Truncated)
                }
            )?;
        self.session.borrow_mut().increment_client_sequence_number();
        Ok(())
    }

    // Send method for TLS Handshake that needs to be encrypted.
    // Does the following things:
    // 1. Encryption
    // 2. Add TLS header in front of application data
    // Input should be inner plaintext
    // Note: Do not put this slice into the transcript hash. It is polluted.
    // TODO: Rename this function. It is only good for client finished
    fn send_application_slice(&self, sockets: &mut SocketSet, slice: &mut [u8]) -> Result<()> {
        let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_send() {
            return Err(Error::Illegal);
        }

        // Borrow session in advance
        let mut client_session = self.session.borrow_mut();

        // Pre-compute TLS record layer as associated_data
        let mut associated_data: [u8; 5] = [0x17, 0x03, 0x03, 0x00, 0x00];
        let auth_tag_length: u16 = match client_session.get_cipher_suite_type() {
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

        let auth_tag = client_session.encrypt_in_place_detached(
            &associated_data,
            slice
        ).map_err(|_| Error::Illegal)?;

        tcp_socket.send_slice(&associated_data)?;
        tcp_socket.send_slice(&slice)?;
        tcp_socket.send_slice(&auth_tag)?;

        client_session.increment_client_sequence_number();
        Ok(())
    }

    // Generic inner recv method, through TCP socket
    // A TCP packet can contain multiple TLS records (including 0)
    // Therefore, sequence nubmer incrementation is not completed here
    fn recv_tls_repr<'a>(&'a self, sockets: &mut SocketSet, byte_array: &'a mut [u8]) -> Result<Vec::<TlsRepr>> {
        let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_recv() {
            return Ok((Vec::new()));
        }
        let array_size = tcp_socket.recv_slice(byte_array)?;
        let mut vec: Vec<TlsRepr> = Vec::new();
        let mut bytes: &[u8] = &byte_array[..array_size];
        loop {
            match parse_tls_repr(bytes) {
                Ok((rest, repr)) => {
                    vec.push(repr);
                    if rest.len() == 0 {
                        return Ok(vec);
                    } else {
                        bytes = rest;
                    }
                },
                _ => return Err(Error::Unrecognized),
            };
        }
    }

    pub fn recv_slice(&self, sockets: &mut SocketSet, data: &mut [u8]) -> Result<usize> {
        let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_recv() {
            return Ok(0);
        }

        let recv_slice_size = tcp_socket.recv_slice(data)?;
        // Encrypted data need a TLS record wrapper (5 bytes)
        // Authentication tag (16 bytes, for all supported AEADs)
        // Content type byte (1 byte)
        // Zero paddings (>=0 bytes)
        if recv_slice_size < 22 {
            return Ok(0);
        }
        
        // Get Associated Data
        let mut session = self.session.borrow_mut();
        let mut associated_data: [u8; 5] = [0; 5];
        associated_data.clone_from_slice(&data[..5]);
        log::info!("Received encrypted appdata: {:?}", &data[..recv_slice_size]);

        // Dump association data (TLS Record wrapper)
        // Only decrypt application data
        // Always increment sequence number after decrpytion
        session.decrypt_application_data_in_place(
            &associated_data,
            &mut data[5..recv_slice_size]
        ).unwrap();
        session.increment_server_sequence_number();

        // Make sure it is application data
        let (content_type, padding_start_index) =
            get_content_type_inner_plaintext(&data[..(recv_slice_size-16)]);

        // If it is not application data, handle it internally
        if content_type != TlsContentType::ApplicationData {
            // TODO:: Implement key update
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

    pub fn send_slice(&self, sockets: &mut SocketSet, data: &[u8]) -> Result<()> {
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
            u16::try_from(data.len()).unwrap()  // Payload length
            + 1                                 // Content type length
            + 16                                // Auth tag length
        );

        // TODO: Dynamically size typed Heapless Vec on socket instantiation,
        // just like MiniMQ
        let mut vec: HeaplessVec<u8, U1024> = HeaplessVec::from_slice(data).unwrap();
        vec.push(0x17);     // Content type
        
        let mut session = self.session.borrow_mut();
        let tag = session.encrypt_application_data_in_place_detached(
            &associated_data,
            &mut vec
        ).unwrap();
        session.increment_client_sequence_number();

        let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
        if !tcp_socket.can_send() {
            return Err(Error::Illegal);
        }

        tcp_socket.send_slice(&associated_data)?;
        tcp_socket.send_slice(&vec)?;
        tcp_socket.send_slice(&tag)?;

        Ok(())
    }
}
