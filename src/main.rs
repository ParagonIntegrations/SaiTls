use smoltcp_tls::tls::TlsSocket;
use smoltcp::socket::TcpSocketBuffer;
use smoltcp::socket::SocketSet;
use smoltcp::wire::Ipv4Address;

use rand_core::RngCore;
use rand_core::CryptoRng;
use rand_core::impls;
use rand_core::Error;

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

	tls_socket.tls_connect(&mut sockets).unwrap();
}