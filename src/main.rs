use smoltcp_tls::tls::TlsSocket;
use smoltcp::socket::TcpSocketBuffer;
use smoltcp::socket::SocketSet;
use smoltcp::wire::Ipv4Address;

use rand_core::RngCore;
use rand_core::CryptoRng;
use rand_core::impls;
use rand_core::Error;

use p256::{EncodedPoint, AffinePoint, ecdh::EphemeralSecret, ecdh::SharedSecret};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use ccm::{Ccm, consts::*};
use aes_gcm::aes::Aes128;
use aes_gcm::{AeadInPlace, NewAead};
use generic_array::GenericArray;
use sha2::{ Digest, Sha256, Sha384, Sha512 };
use heapless::Vec;
use hkdf::Hkdf;

use smoltcp_tls::key::*;
use smoltcp_tls::buffer::TlsBuffer;

mod encrypted;
use encrypted::ENCRYPTED_DATA;

struct CountingRng(u64);

impl RngCore for CountingRng {
	fn next_u32(&mut self) -> u32 {
		self.next_u64() as u32
	}

	fn next_u64(&mut self) -> u64 {
		self.0 += 1;
		self.0
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		impls::fill_bytes_via_next(self, dest)
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
		Ok(self.fill_bytes(dest))
	}
}

impl CryptoRng for CountingRng {}

static mut RNG: CountingRng = CountingRng(0);

fn main() {
	let mut socket_set_entries: [_; 8] = Default::default();
	let mut sockets = SocketSet::new(&mut socket_set_entries[..]);

	let mut tx_storage = [0; 4096];
	let mut rx_storage = [0; 4096];

	let mut tls_socket = unsafe {
		let tx_buffer = TcpSocketBuffer::new(&mut tx_storage[..]);
		let rx_buffer = TcpSocketBuffer::new(&mut rx_storage[..]);
		TlsSocket::new(
			&mut sockets,
			rx_buffer,
			tx_buffer,
			&mut RNG,
		)
	};

	tls_socket.tcp_connect(
		&mut sockets,
		(Ipv4Address::new(192, 168, 1, 125), 1883),
		49600
	).unwrap();

//	tls_socket.tls_connect(&mut sockets).unwrap();

	let psk: [u8; 32] = [0; 32];
	let early_secret = Hkdf::<Sha256>::new(None, &psk);
	let derived_secret = derive_secret(
		&early_secret,
		"derived",
		Sha256::new().chain("")
	);
	let (handshake_secret, handshake_secret_hkdf) = Hkdf::<Sha256>::extract(
		Some(&derived_secret),
		&SHARED_SECRET
	);
	let client_handshake_traffic_secret = {
		let hkdf_label = HkdfLabel {
			length: 32,
			label_length: 18,
			label: b"tls13 c hs traffic",
			context_length: 32,
			context: &HELLO_HASH,
		};
		let mut array = [0; 100];
		let mut buffer = TlsBuffer::new(&mut array);
		buffer.enqueue_hkdf_label(hkdf_label);
		let info: &[u8] = buffer.into();

		// Define output key material (OKM), dynamically sized by hash
		let mut okm: GenericArray<u8, U32> = GenericArray::default();
		handshake_secret_hkdf.expand(info, &mut okm).unwrap();
		okm
	};
	let server_handshake_traffic_secret = {
		let hkdf_label = HkdfLabel {
			length: 32,
			label_length: 18,
			label: b"tls13 s hs traffic",
			context_length: 32,
			context: &HELLO_HASH,
		};
		let mut array = [0; 100];
		let mut buffer = TlsBuffer::new(&mut array);
		buffer.enqueue_hkdf_label(hkdf_label);
		let info: &[u8] = buffer.into();

		// Define output key material (OKM), dynamically sized by hash
		let mut okm: GenericArray<u8, U32> = GenericArray::default();
		handshake_secret_hkdf.expand(info, &mut okm).unwrap();
		okm
	};
	let server_handshake_write_key = {
		let hkdf_label = HkdfLabel {
			length: 16,
			label_length: 9,
			label: b"tls13 key",
			context_length: 0,
			context: b"",
		};
		let mut array = [0; 100];
		let mut buffer = TlsBuffer::new(&mut array);
		buffer.enqueue_hkdf_label(hkdf_label);
		let info: &[u8] = buffer.into();

		// Define output key material (OKM), dynamically sized by hash
		let mut okm: GenericArray<u8, U16> = GenericArray::default();
		Hkdf::<Sha256>::from_prk(&server_handshake_traffic_secret)
			.unwrap()
			.expand(info, &mut okm);
		okm
	};
	let server_handshake_write_iv = {
		let hkdf_label = HkdfLabel {
			length: 12,
			label_length: 8,
			label: b"tls13 iv",
			context_length: 0,
			context: b"",
		};
		let mut array = [0; 100];
		let mut buffer = TlsBuffer::new(&mut array);
		buffer.enqueue_hkdf_label(hkdf_label);
		let info: &[u8] = buffer.into();

		// Define output key material (OKM), dynamically sized by hash
		let mut okm: GenericArray<u8, U12> = GenericArray::default();
		Hkdf::<Sha256>::from_prk(&server_handshake_traffic_secret)
			.unwrap()
			.expand(info, &mut okm);
		okm
	};
	let cipher: Aes128Gcm = Aes128Gcm::new(&server_handshake_write_key);
	let decrypted_data = {
		let mut vec: Vec<u8, U2048> = Vec::from_slice(&ENCRYPTED_DATA).unwrap();
		cipher.decrypt_in_place(
			&server_handshake_write_iv,
			&[
				0x17, 0x03, 0x03, 0x04, 0x75
			],
			&mut vec
		).unwrap();
		vec
	};

	println!("{:x?}", client_handshake_traffic_secret);
	println!("{:x?}", server_handshake_traffic_secret);
	println!("{:x?}", server_handshake_write_key);
	println!("{:x?}", server_handshake_write_iv);
	println!("{:x?}", decrypted_data);

}

const SHARED_SECRET: [u8; 32] = [
	0xdf, 0x4a, 0x29, 0x1b, 0xaa, 0x1e, 0xb7, 0xcf,
	0xa6, 0x93, 0x4b, 0x29, 0xb4, 0x74, 0xba, 0xad,
	0x26, 0x97, 0xe2, 0x9f, 0x1f, 0x92, 0x0d, 0xcc,
	0x77, 0xc8, 0xa0, 0xa0, 0x88, 0x44, 0x76, 0x24
];

const HELLO_HASH: [u8; 32] = [
	0xda, 0x75, 0xce, 0x11, 0x39, 0xac, 0x80, 0xda,
	0xe4, 0x04, 0x4d, 0xa9, 0x32, 0x35, 0x0c, 0xf6,
	0x5c, 0x97, 0xcc, 0xc9, 0xe3, 0x3f, 0x1e, 0x6f,
	0x7d, 0x2d, 0x4b, 0x18, 0xb7, 0x36, 0xff, 0xd5
];