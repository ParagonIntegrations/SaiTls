use smoltcp_tls::tls::TlsSocket;
use smoltcp::socket::TcpSocketBuffer;
use smoltcp::socket::SocketSet;
use smoltcp::wire::Ipv4Address;

fn main() {
	let mut socket_set_entries: [_; 8] = Default::default();
	let mut sockets = SocketSet::new(&mut socket_set_entries[..]);

	let mut tx_storage = [0; 4096];
	let mut rx_storage = [0; 4096];

	let mut tls_socket = {
		let tx_buffer = TcpSocketBuffer::new(&mut tx_storage[..]);
		let rx_buffer = TcpSocketBuffer::new(&mut rx_storage[..]);
		TlsSocket::new(
			&mut sockets,
			rx_buffer,
			tx_buffer
		)
	};

	tls_socket.tcp_connect(
		&mut sockets,
		(Ipv4Address::new(192, 168, 1, 125), 1883),
		49600
	).unwrap();

	tls_socket.tls_connect(&mut sockets).unwrap();
}