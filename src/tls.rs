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

use alloc::vec::{ self, Vec };

use crate::Error as TlsError;
use crate::tls_packet::*;
use crate::parse::parse_tls_repr;
use crate::cipher_suite::CipherSuite;
use crate::buffer::TlsBuffer;
use crate::session::{Session, TlsRole};

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
	CONNECTED,
}

// TODO: Group up all session_specific parameters into a separate structure
pub struct TlsSocket<R: 'static + RngCore + CryptoRng>
{
	state: RefCell<TlsState>,
	tcp_handle: SocketHandle,
	rng: R,
	secret: RefCell<Option<EphemeralSecret>>,	// Used enum Option to allow later init
	session_id: RefCell<Option<[u8; 32]>>,		// init session specific field later
	received_change_cipher_spec: RefCell<Option<bool>>,
	cipher: RefCell<Option<CipherSuite>>,
	handshake_sha256: RefCell<Sha256>,
	session: RefCell<Session>,
}

impl<R: RngCore + CryptoRng> TlsSocket<R> {
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
			state: RefCell::new(TlsState::START),
			tcp_handle,
			rng,
			secret: RefCell::new(None),
			session_id: RefCell::new(None),
			received_change_cipher_spec: RefCell::new(None),
			cipher: RefCell::new(None),
			handshake_sha256: RefCell::new(Sha256::new()),
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
		let state = self.state.clone().into_inner();
		match state {
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
					.client_hello(&ecdh_secret, random, session_id);

				// Update hash function with client hello handshake
				let mut array = [0; 2048];
				let mut buffer = TlsBuffer::new(&mut array);
				buffer.enqueue_tls_repr(repr)?;
				let slice: &[u8] = buffer.into();

				// Update hash by handshake
				// Update with entire packet except the record layer
				{
					self.handshake_sha256.borrow_mut().update(&slice[5..]);
				}
				self.send_tls_slice(sockets, slice)?;

				// Store session settings, i.e. secret, session_id
				self.secret.replace(Some(ecdh_secret));
				self.session_id.replace(Some(session_id));
				self.received_change_cipher_spec.replace(Some(false));

				// Update the TLS state
				self.state.replace(TlsState::WAIT_SH);
			},
			// TLS Client wait for Server Hello
			// No need to send anything
			TlsState::WAIT_SH => {},
			// TLS Client wait for certificate from TLS server
			// No need to send anything
			// Note: TLS server should normall send SH alongside EE
			// TLS client should jump from WAIT_SH directly to WAIT_CERT_CR directly.
			TlsState::WAIT_EE => {},
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

		Ok(self.state.clone().into_inner() == TlsState::CONNECTED)
	}

	// Process TLS ingress during handshake
	fn process(&self, repr: TlsRepr) -> Result<()> {
		let state = self.state.clone().into_inner();

		// Change_cipher_spec check:
		// Must receive CCS before recv peer's FINISH message
		// i.e. Must happen after START and before CONNECTED
		//
		// CCS message only exist for compatibility reason,
		// Drop the message and update `received_change_cipher_spec`
		if repr.is_change_cipher_spec() {
			self.received_change_cipher_spec.replace(Some(true));
			return Ok(())
		}

		match state {
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
					//		(TODO: Support other key shares, e.g. X25519)
					// session_id_echo: should be same as the one sent by client
					// cipher_suite: Store
					//		(TODO: Check if such suite was offered)
					// compression_method: Must be null, not supported in TLS 1.3
					//
					// Check extensions:
					// supported_version: Must be TLS 1.3
					// key_share: Store key, must be in secp256r1
					//		(TODO: Support other key shares ^)
					let handshake_data = &repr.handshake.as_ref().unwrap().handshake_data;
					if let HandshakeData::ServerHello(server_hello) = handshake_data {
						// Check random: Cannot be SHA-256 of "HelloRetryRequest"
						if server_hello.random == HRR_RANDOM {
							// Abort communication
							todo!()
						}
						// Check session_id_echo
						// The socket should have a session_id after moving from START state
						if self.session_id.clone().into_inner().unwrap() != server_hello.session_id_echo {
							// Abort communication
							todo!()
						}
						// Store the cipher suite
						let selected_cipher = server_hello.cipher_suite;
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
									let server_public = EncodedPoint::from_untagged_bytes(
										GenericArray::from_slice(&server_share.key_exchange[1..])
									);
									// TODO: Handle improper shared key
									// Right now is causes a panic, only socket abort is needed
									let secret = self.secret.replace(None);
									let shared = secret.unwrap()
										.diffie_hellman(&server_public)
										.expect("Unsupported key");
									// let cipher = match selected_cipher {
									// 	CipherSuite::TLS_AES_128_GCM_SHA256 => {
									// 		Cipher::TLS_AES_128_GCM_SHA256(
									// 			todo!()
									// 		)
									// 	},
									// 	CipherSuite::TLS_AES_256_GCM_SHA384 => {
									// 		Cipher::TLS_AES_256_GCM_SHA384(
									// 			Aes256Gcm::new(shared.as_bytes())
									// 		)
									// 	},
									// 	CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
									// 		Cipher::TLS_CHACHA20_POLY1305_SHA256(
									// 			ChaCha20Poly1305::new(shared.as_bytes())
									// 		)
									// 	},
									// 	CipherSuite::TLS_AES_128_CCM_SHA256 => {
									// 		Cipher::TLS_AES_128_CCM_SHA256(
									// 			todo!()
									// 		)
									// 	},
									// 	// CCM_8 is not supported
									// 	// TODO: Abort communication
									// 	CipherSuite::TLS_AES_128_CCM_8_SHA256 => {
									// 		todo!()
									// 	}
									// };
									// self.cipher.replace(Some(cipher));
								}
							}
						}

					} else {
						// Handle invalid TLS packet
						todo!()
					}

					// This is indeed a desirable ServerHello TLS repr
					// Reprocess ServerHello into a slice
					// Update SHA256 hasher with the slice
					let mut array = [0; 2048];
					let mut buffer = TlsBuffer::new(&mut array);
					buffer.enqueue_tls_repr(repr);
					let slice: &[u8] = buffer.into();
					{
						self.handshake_sha256
							.borrow_mut()
							.update(&slice[5..]);
					}
					
					// Update TLS session state
					self.state.replace(TlsState::WAIT_EE);
				}
			},

			// Expect encrypted extensions after receiving SH
			TlsState::WAIT_EE => {
				// ExcepytedExtensions are disguised as ApplicationData
				// Pull out the `payload` from TlsRepr, decrypt as EE
			},

			_ => {},
		}

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
		tcp_socket.send_slice(buffer.into())
			.and_then(
				|size| if size == buffer_size {
					Ok(())
				} else {
					Err(Error::Truncated)
				}
			)
	}

	// Generic inner send method for buffer IO, through TCP socket
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
			)
	}

	// Generic inner recv method, through TCP socket
	// A TCP packet can contain multiple TLS segments
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
}
