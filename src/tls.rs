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

use byteorder::{ByteOrder, NetworkEndian, BigEndian, WriteBytesExt};

use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use heapless::Vec;
use heapless::consts::*;

use core::convert::TryInto;
use core::convert::TryFrom;

use crate::tls_packet::*;
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

pub struct TlsSocket
{
	state: TlsState,
	tcp_handle: SocketHandle,
	random: ChaCha20Rng,
}

impl TlsSocket {
	pub fn new<'a, 'b, 'c>(
		sockets: &mut SocketSet<'a, 'b, 'c>,
		rx_buffer: TcpSocketBuffer<'b>,
		tx_buffer: TcpSocketBuffer<'b>,
	) -> Self
	where
		'b: 'c,
	{
		let tcp_socket = TcpSocket::new(rx_buffer, tx_buffer);
		let tcp_handle = sockets.add(tcp_socket);
		TlsSocket {
			state: TlsState::START,
			tcp_handle,
			random: ChaCha20Rng::from_entropy(),
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
		tcp_socket.connect(remote_endpoint, local_endpoint)
	}

	pub fn tls_connect(&mut self, sockets: &mut SocketSet) -> Result<bool> {
		// Check tcp_socket connectivity
		{
			let tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
			if tcp_socket.state() != TcpState::Established {
				return Ok(false);
			}
		}

		if self.state == TlsState::START {
			// Create TLS representation, length and payload not finalised
			let mut random: [u8; 32] = [0; 32];
			let mut session_id: [u8; 32] = [0; 32];
			self.random.fill_bytes(&mut random);
			self.random.fill_bytes(&mut session_id);

			let cipher_suites_length = 3;
			let cipher_suites = [
				CipherSuite::TLS_AES_128_GCM_SHA256,
				CipherSuite::TLS_AES_256_GCM_SHA384,
				CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
			];

			// Length: to be determined
			let supported_versions_extension = Extension {
				extension_type: ExtensionType::SupportedVersions,
				length: 3,
				extension_data: &[
					2,  // Number of supported versions * 2
					// Need 2 bytes to contain a version
					0x03, 0x04  // 0x0303: TLS Version 1.3
				]
			};

			let client_hello = ClientHello {
				version: TlsVersion::Tls12,
				random,
				session_id_length: 32,
				session_id,
				cipher_suites_length,
				cipher_suites: &cipher_suites,
				compression_method_length: 1,
				compression_methods: 0,
				extension_length: supported_versions_extension.get_length(),
				extensions: &[supported_versions_extension],
			};

			let handshake_repr = HandshakeRepr {
				msg_type: HandshakeType::ClientHello,
				length: client_hello.get_length(),
				handshake_data: HandshakeData::ClientHello(client_hello),
			};

			let repr = TlsRepr {
				content_type: TlsContentType::Handshake,
				version: TlsVersion::Tls13,
				length: 0,
				payload: None,
				handshake: Some(handshake_repr),
			};

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
	fn recv_tls_repr<'a>(&'a mut self, sockets: &mut SocketSet, byte_array: &'a mut [u8]) -> Result<TlsRepr<'a, '_>> {
		let mut tcp_socket = sockets.get::<TcpSocket>(self.tcp_handle);
		let size = tcp_socket.recv_slice(byte_array)?;
		let buffer = TlsBuffer::new(&mut byte_array[..size]);
		buffer.dequeue_tls_repr()
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

	fn enqueue_tls_repr(&mut self, tls_repr: TlsRepr) -> Result<()> {
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

	fn enqueue_handshake_repr(&mut self, handshake_repr: HandshakeRepr) -> Result<()> {
		self.write_u8(handshake_repr.msg_type.into())?;
		self.write_u24(handshake_repr.length)?;
		self.enqueue_handshake_data(handshake_repr.handshake_data)
	}

	fn enqueue_handshake_data(&mut self, handshake_data: HandshakeData) -> Result<()> {
		match handshake_data {
			HandshakeData::ClientHello(client_hello) => {
				self.enqueue_client_hello(client_hello)
			}
			_ => {
				Err(Error::Unrecognized)
			}
		}
	}

	fn enqueue_client_hello(&mut self, client_hello: ClientHello) -> Result<()> {
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

	fn enqueue_extensions(&mut self, extensions: &[Extension]) -> Result<()> {
		for extension in extensions {
			self.write_u16(extension.extension_type.into())?;
			self.write_u16(extension.length)?;
			self.write(extension.extension_data)?;
		}
		Ok(())
	}

	fn dequeue_tls_repr<'b>(mut self) -> Result<TlsRepr<'a, 'b>> {
		// Create a TLS Representation layer
		// Modify the representation along the way
		let mut repr = TlsRepr {
			content_type: TlsContentType::Invalid,
			version: TlsVersion::Tls10,
			length: 0,
			payload: None,
			handshake: None,
		};

		repr.content_type = TlsContentType::try_from(self.read_u8()?)
			.map_err(|_| Error::Unrecognized)?;
		repr.version = TlsVersion::try_from(self.read_u16()?)
			.map_err(|_| Error::Unrecognized)?;
		repr.length = self.read_u16()?;

		use TlsContentType::*;
		match repr.content_type {
			Invalid => Err(Error::Unrecognized),
			ChangeCipherSpec | Alert => unimplemented!(),
			Handshake => todo!(),
			ApplicationData => {
				repr.payload = Some(self.read_all());
				Ok(repr)
			}
		}
	}

	fn dequeue_handshake<'b>(mut self) -> Result<HandshakeRepr<'a, 'b>> {
		// Create a Handshake header representation
		// Fill in proper value afterwards
		let mut repr = HandshakeRepr {
			msg_type: HandshakeType::ClientHello,
			length: 0,
			handshake_data: HandshakeData::Uninitialized,
		};

		repr.msg_type = HandshakeType::try_from(self.read_u8()?)
			.map_err(|_| Error::Unrecognized)?;
		repr.length = self.read_u24()?;

		use HandshakeType::*;
		match repr.msg_type {
			ClientHello => unimplemented!(),
			ServerHello => todo!(),
			_ => unimplemented!(),
		}
	}

	fn dequeue_server_hello(mut self) -> Result<ServerHello<'static, 'static>> {
		// Create a Server Hello representation
		// Fill in proper value afterwards
		let mut server_hello = ServerHello {
			version: TlsVersion::Tls10,
			random: [0; 32],
			session_id_echo_length: 0,
			session_id_echo: [0; 32],
			cipher_suite: CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
			compression_method: 0,
			extension_length: 0,
			extensions: &[],
		};

		server_hello.version = TlsVersion::try_from(self.read_u16()?)
			.map_err(|_| Error::Unrecognized)?;
		for random_byte in &mut server_hello.random[..] {
			*random_byte = self.read_u8()?;
		}
		server_hello.session_id_echo_length = self.read_u8()?;
		for id_byte in &mut server_hello.session_id_echo[
			..usize::try_from(server_hello.session_id_echo_length)
				.map_err(|_| Error::Exhausted)?
			] {
			*id_byte = self.read_u8()?;
		}
		server_hello.cipher_suite = CipherSuite::try_from(self.read_u16()?)
			.map_err(|_| Error::Unrecognized)?;
		server_hello.compression_method = self.read_u8()?;
		server_hello.extension_length = self.read_u16()?;

		let mut remaining_length = server_hello.extension_length;
		let mut extension_counter = 0;
		let mut extension_vec: Vec<Extension, U32> = Vec::new();
		while remaining_length != 0 {
			extension_vec.push(self.dequeue_extension()?.clone())
				.map_err(|_| Error::Exhausted)?;
			// Deduct base length of an extension (ext_type, len)
			remaining_length -= 4;
			remaining_length -= extension_vec[extension_counter].length;
			extension_counter += 1;
		}

		Ok(server_hello)
	}

	fn dequeue_extension(&self) -> Result<Extension<'_>> {
		// Create an Extension representation
		// Fill in proper value afterwards
		let mut extension = Extension {
			extension_type: ExtensionType::ServerName,
			length: 0,
			extension_data: &[],
		};

		extension.extension_type = ExtensionType::try_from(self.read_u16()?)
			.map_err(|_| Error::Unrecognized)?;
		extension.length = self.read_u16()?;
		extension.extension_data = self.read_slice(
			usize::try_from(extension.length)
				.map_err(|_| Error::Exhausted)?
		)?;
		Ok(extension)
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
