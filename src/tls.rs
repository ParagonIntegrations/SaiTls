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

use core::convert::TryInto;
use core::convert::TryFrom;

use rand_core::{RngCore, CryptoRng};
use p256::{EncodedPoint, AffinePoint, ecdh::EphemeralSecret};

use alloc::vec::{ self, Vec };

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

pub struct TlsSocket<R: 'static + RngCore + CryptoRng>
{
	state: TlsState,
	tcp_handle: SocketHandle,
	rng: R,
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
			state: TlsState::START,
			tcp_handle,
			rng,
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

		if self.state == TlsState::START {
			// Create TLS representation, length and payload not finalised
			let mut random: [u8; 32] = [0; 32];
			self.rng.fill_bytes(&mut random);
			let mut session_id: [u8; 32] = [0; 32];
			self.rng.fill_bytes(&mut session_id);

			let cipher_suites_length = 6;
			let cipher_suites = [
				CipherSuite::TLS_AES_128_GCM_SHA256,
				CipherSuite::TLS_AES_256_GCM_SHA384,
				CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
			];

			// Length: to be determined
			let supported_versions_extension = Extension {
				extension_type: ExtensionType::SupportedVersions,
				length: 5,
				extension_data: &[
					4,  // Number of supported versions * 2
					// Need 2 bytes to contain a version
					0x03, 0x04,		// 0x0304: TLS Version 1.3
					0x03, 0x03,		// 0x0303: TLS version 1.2
				]
			};

			let signature_algorithms_extension = Extension {
				extension_type: ExtensionType::SignatureAlgorithms,
				length: 24,
				extension_data: &[
					0x00, 22,			// Length in bytes
					0x04, 0x03,			// ecdsa_secp256r1_sha256
					0x08, 0x07,			// ed25519
					0x08, 0x09,			// rsa_pss_pss_sha256
					0x04, 0x01,			// rsa_pkcs1_sha256
					0x08, 0x04,			// rsa_pss_rsae_sha256
					0x08, 0x0a,			// rsa_pss_pss_sha384
					0x05, 0x01,			// rsa_pkcs1_sha384
					0x08, 0x05,			// rsa_pss_rsae_sha384
					0x08, 0x0b,			// rsa_pss_pss_sha512
					0x06, 0x01,			// rsa_pkcs1_sha512
					0x08, 0x06,			// rsa_pss_rsae_sha512
				]
			};

			let supported_groups_extension = Extension {
				extension_type: ExtensionType::SupportedGroups,
				length: 4,
				extension_data: &[
					0x00, 0x02,			// Length in bytes
					0x00, 0x17,			// secp256r1
				]
			};

			let key_share_extension = Extension {
				extension_type: ExtensionType::KeyShare,
				length: 71,
				extension_data: &{
					let ecdh_secret = unsafe { EphemeralSecret::random(&mut self.rng) };
					let ecdh_public = EncodedPoint::from(&ecdh_secret);
					let x_coor = ecdh_public.x();
					let y_coor = ecdh_public.y().unwrap();
					let mut data: [u8; 71] = [0; 71];
					data[0..2].copy_from_slice(&[0x00, 69]);	// Length in bytes
					data[2..4].copy_from_slice(&[0x00, 0x17]);	// secp256r1
					data[4..6].copy_from_slice(&[0x00, 65]);	// key exchange length
					data[6..7].copy_from_slice(&[0x04]);		// Fixed legacy value
					data[7..39].copy_from_slice(&x_coor);
					data[39..71].copy_from_slice(&y_coor);
					data
				}
			};

			let psk_key_exchange_modes_extension = Extension {
				extension_type: ExtensionType::PSKKeyExchangeModes,
				length: 2,
				extension_data: &[
					0x01,				// Length in bytes
					0x01,				// psk_dhe_ke
				]
			};

			let mut client_hello = ClientHello {
				version: TlsVersion::Tls12,
				random,
				session_id_length: 32,
				session_id,
				cipher_suites_length,
				cipher_suites: &cipher_suites,
				compression_method_length: 1,
				compression_methods: 0,
				extension_length: supported_versions_extension.get_length().try_into().unwrap(),
				extensions: vec![
					supported_versions_extension,
					signature_algorithms_extension,
					supported_groups_extension,
					psk_key_exchange_modes_extension,
					key_share_extension
				]
			};

			client_hello.extension_length = {
				let mut sum = 0;
				for ext in client_hello.extensions.iter() {
					sum += ext.get_length();
				}
				sum.try_into().unwrap()
			};

			let handshake_repr = HandshakeRepr {
				msg_type: HandshakeType::ClientHello,
				length: client_hello.get_length(),
				handshake_data: HandshakeData::ClientHello(client_hello),
			};

			let repr = TlsRepr {
				content_type: TlsContentType::Handshake,
				version: TlsVersion::Tls10,
				length: handshake_repr.get_length(),
				payload: None,
				handshake: Some(handshake_repr),
			};

			log::info!("{:?}", repr);

			self.send_tls_repr(sockets, repr)?;
			self.state = TlsState::WAIT_SH;
			Ok(true)
		} else if self.state == TlsState::WAIT_SH {
			Ok(true)
		} else {
			Ok(true)
		}
	}

	// Generic inner send method, through TCP socket
	fn send_tls_repr(&mut self, sockets: &mut SocketSet, tls_repr: TlsRepr) -> Result<()> {
		let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
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
	fn recv_tls_repr<'a>(&'a mut self, sockets: &mut SocketSet, byte_array: &'a mut [u8]) -> Result<Vec::<TlsRepr>> {
		let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
		tcp_socket.recv_slice(byte_array)?;
		let mut vec: Vec<TlsRepr> = Vec::new();

		let mut bytes: &[u8] = byte_array;
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
			self.write(extension.extension_data)?;
		}
		Ok(())
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
