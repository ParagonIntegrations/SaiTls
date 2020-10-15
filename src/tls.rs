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

use alloc::vec::{ self, Vec };

use crate::Error as TlsError;
use crate::tls_packet::*;
use crate::parse::parse_tls_repr;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
enum TlsState {
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
	cipher: RefCell<Option<Cipher>>,
}

pub(crate) enum Cipher {
	TLS_AES_128_GCM_SHA256(Aes128Gcm),
	TLS_AES_256_GCM_SHA384(Aes256Gcm),
	TLS_CHACHA20_POLY1305_SHA256(ChaCha20Poly1305),
	TLS_AES_128_CCM_SHA256(Ccm<Aes128, U16, U12>)
}

macro_rules! impl_cipher {
	($($cipher_name: ident),+) => {
		impl Cipher {
			pub(crate) fn encrypt<T>(&self, rng: &mut T, associated_data: &[u8], buffer: &mut Vec<u8>) -> core::result::Result<(), TlsError>
			where
				T: RngCore + CryptoRng
			{
				// All 4 supported Ciphers use a nonce of 12 bytes
				let mut nonce_array: [u8; 12] = [0; 12];
				rng.fill_bytes(&mut nonce_array);
				use Cipher::*;
				match self {
					$(
						$cipher_name(cipher) => {
							cipher.encrypt_in_place(
								&GenericArray::from_slice(&nonce_array),
								associated_data,
								buffer
							).map_err(
								|_| TlsError::EncryptionError
							)
						}
					)+
				}
			}

			pub(crate) fn decrypt<T>(&self, rng: &mut T, associated_data: &[u8], buffer: &mut Vec<u8>) -> core::result::Result<(), TlsError>
			where
				T: RngCore + CryptoRng
			{
				// All 4 supported Ciphers use a nonce of 12 bytes
				let mut nonce_array: [u8; 12] = [0; 12];
				rng.fill_bytes(&mut nonce_array);
				use Cipher::*;
				match self {
					$(
						$cipher_name(cipher) => {
							cipher.decrypt_in_place(
								&GenericArray::from_slice(&nonce_array),
								associated_data,
								buffer
							).map_err(
								|_| TlsError::EncryptionError
							)
						}
					)+
				}
			}
		}
	}
}

impl_cipher!(
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_CCM_SHA256
);

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
				self.send_tls_repr(sockets, repr)?;

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
		let tls_repr_vec = self.recv_tls_repr(sockets, &mut array)?;

		for repr in tls_repr_vec.iter() {
			self.process(repr)?;
		}

		Ok(self.state.clone().into_inner() == TlsState::CONNECTED)
	}

	// Process TLS ingress during handshake
	fn process(&self, repr: &TlsRepr) -> Result<()> {
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
									let cipher = match selected_cipher {
										CipherSuite::TLS_AES_256_GCM_SHA384 => {
											Cipher::TLS_AES_256_GCM_SHA384(
												Aes256Gcm::new(shared.as_bytes())
											)
										}
										_ => todo!()
									};
									self.cipher.replace(Some(cipher));
								}
							}
						}
						self.state.replace(TlsState::WAIT_EE);

					} else {
						// Handle invalid TLS packet
						todo!()
					}

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
		let buffer_size = buffer.index.clone();
		tcp_socket.send_slice(buffer.into())
			.and_then(
				|size| if size == buffer_size.into_inner() {
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

// Only designed to support read or write the entire buffer
pub(crate) struct TlsBuffer<'a> {
	buffer: &'a mut [u8],
	index: core::cell::RefCell<usize>,
}

impl<'a> Into<&'a [u8]> for TlsBuffer<'a> {
	fn into(self) -> &'a [u8] {
		&self.buffer[0..self.index.into_inner()]
	}
}

impl<'a> TlsBuffer<'a> {
	pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
		Self {
			buffer,
			index: core::cell::RefCell::new(0),
		}
	}

	pub(crate) fn write(&mut self, data: &[u8]) -> Result<()> {
		let mut index = self.index.borrow_mut();
		if (self.buffer.len() - *index) < data.len() {
			return Err(Error::Exhausted);
		}
		let next_index = *index + data.len();
		self.buffer[*index..next_index].copy_from_slice(data);
		*index = next_index;
		Ok(())
	}

	pub(crate) fn write_u8(&mut self, data: u8) -> Result<()> {
		let mut index = self.index.borrow_mut();
		if (self.buffer.len() - *index) < 1 {
			return Err(Error::Exhausted);
		}
		self.buffer[*index] = data;
		*index += 1;
		Ok(())
	}

	pub(crate) fn read_u8(&mut self) -> Result<u8> {
		let mut index = self.index.borrow_mut();
		if (self.buffer.len() - *index) < 1 {
			return Err(Error::Exhausted);
		}
		let data = self.buffer[*index];
		*index += 1;
		Ok(data)
	}

	pub(crate) fn read_all(self) -> &'a [u8] {
		&self.buffer[self.index.into_inner()..]
	}

	pub(crate) fn read_slice(&self, length: usize) -> Result<&[u8]> {
		let mut index = self.index.borrow_mut();
		if (self.buffer.len() - *index) < length {
			return Err(Error::Exhausted);
		}
		let next_index = *index + length;
		let slice = &self.buffer[*index..next_index];
		*index = next_index;
		Ok(slice)
	}

	fn enqueue_tls_repr(&mut self, tls_repr: TlsRepr<'a>) -> Result<()> {
		self.write_u8(tls_repr.content_type.into())?;
		self.write_u16(tls_repr.version.into())?;
		self.write_u16(tls_repr.length)?;
		if let Some(app_data) = tls_repr.payload {
			self.write(app_data)?;
		} else if let Some(handshake_repr) = tls_repr.handshake {
			// Queue handshake_repr into buffer
			self.enqueue_handshake_repr(handshake_repr)?;
		} else {
			return Err(Error::Malformed);
		}
		Ok(())
	}

	fn enqueue_handshake_repr(&mut self, handshake_repr: HandshakeRepr<'a>) -> Result<()> {
		self.write_u8(handshake_repr.msg_type.into())?;
		self.write_u24(handshake_repr.length)?;
		self.enqueue_handshake_data(handshake_repr.handshake_data)
	}

	fn enqueue_handshake_data(&mut self, handshake_data: HandshakeData<'a>) -> Result<()> {
		match handshake_data {
			HandshakeData::ClientHello(client_hello) => {
				self.enqueue_client_hello(client_hello)
			}
			_ => {
				Err(Error::Unrecognized)
			}
		}
	}

	fn enqueue_client_hello(&mut self, client_hello: ClientHello<'a>) -> Result<()> {
		self.write_u16(client_hello.version.into())?;
		self.write(&client_hello.random)?;
		self.write_u8(client_hello.session_id_length)?;
		self.write(&client_hello.session_id)?;
		self.write_u16(client_hello.cipher_suites_length)?;
		for suite in client_hello.cipher_suites.iter() {
			self.write_u16((*suite).into())?;
		}
		self.write_u8(client_hello.compression_method_length)?;
		self.write_u8(client_hello.compression_methods)?;
		self.write_u16(client_hello.extension_length)?;
		self.enqueue_extensions(client_hello.extensions)
	}

	fn enqueue_extensions(&mut self, extensions: Vec<Extension>) -> Result<()> {
		for extension in extensions {
			self.write_u16(extension.extension_type.into())?;
			self.write_u16(extension.length)?;
			self.enqueue_extension_data(extension.extension_data)?;
		}
		Ok(())
	}

	fn enqueue_extension_data(&mut self, extension_data: ExtensionData) -> Result<()> {
		use crate::tls_packet::ExtensionData::*;
		match extension_data {
			SupportedVersions(s) => {
				use crate::tls_packet::SupportedVersions::*;
				match s {
					ClientHello { length, versions } => {
						self.write_u8(length)?;
						for version in versions.iter() {
							self.write_u16((*version).into())?;
						}
					},
					ServerHello { selected_version } => {
						self.write_u16(selected_version.into())?;
					}
				}
			},
			SignatureAlgorithms(s) => {
				self.write_u16(s.length)?;
				for sig_alg in s.supported_signature_algorithms.iter() {
					self.write_u16((*sig_alg).into())?;
				}
			},
			NegotiatedGroups(n) => {
				self.write_u16(n.length)?;
				for group in n.named_group_list.iter() {
					self.write_u16((*group).into())?;
				}
			},
			KeyShareEntry(k) => {
				let mut key_share_entry_into = |buffer: &mut TlsBuffer, entry: crate::tls_packet::KeyShareEntry| {
					buffer.write_u16(entry.group.into())?;
					buffer.write_u16(entry.length)?;
					buffer.write(entry.key_exchange.as_slice())
				};

				use crate::tls_packet::KeyShareEntryContent::*;
				match k {
					KeyShareClientHello { length, client_shares } => {
						self.write_u16(length)?;
						for share in client_shares.iter() {
							self.enqueue_key_share_entry(share)?;
						}
					}
					KeyShareHelloRetryRequest { selected_group } => {
						self.write_u16(selected_group.into())?;
					}
					KeyShareServerHello { server_share } => {
						self.enqueue_key_share_entry(&server_share)?;
					}
				}
			},

			// TODO: Implement buffer formatting for other extensions
			_ => todo!()
		};
		Ok(())
	}

	fn enqueue_key_share_entry(&mut self, entry: &crate::tls_packet::KeyShareEntry) -> Result<()> {
		self.write_u16(entry.group.into())?;
		self.write_u16(entry.length)?;
		self.write(entry.key_exchange.as_slice())
	}
}

macro_rules! export_byte_order_fn {
	($($write_fn_name: ident, $read_fn_name: ident, $data_type: ty, $data_size: literal),+) => {
		impl<'a> TlsBuffer<'a> {
			$(
				pub(crate) fn $write_fn_name(&mut self, data: $data_type) -> Result<()> {
					let mut index = self.index.borrow_mut();
					if (self.buffer.len() - *index) < $data_size {
						return Err(Error::Exhausted);
					}
					let next_index = *index + $data_size;
					NetworkEndian::$write_fn_name(&mut self.buffer[*index..next_index], data);
					*index = next_index;
					Ok(())
				}

				pub(crate) fn $read_fn_name(&self) -> Result<$data_type> {
					let mut index = self.index.borrow_mut();
					if (self.buffer.len() - *index) < $data_size {
						return Err(Error::Exhausted);
					}
					let next_index = *index + $data_size;
					let data = NetworkEndian::$read_fn_name(&self.buffer[*index..next_index]);
					*index = next_index;
					Ok(data)
				}
			)+
		}
	}
}

export_byte_order_fn!(
	write_u16,  read_u16,   u16,    2,
	write_u24,  read_u24,   u32,    3,
	write_u32,  read_u32,   u32,    4,
	write_u48,  read_u48,   u64,    6,
	write_u64,  read_u64,   u64,    8
);
