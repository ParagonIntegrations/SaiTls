use embedded_nal_tcp_stack as nal;
use smoltcp as net;

use crate::set::TlsSocketHandle as SocketHandle;
use crate::set::TlsSocketSet as SocketSet;

use nal::{TcpStack, Mode, SocketAddr, nb};
use net::iface::EthernetInterface;
use net::time::Instant;
use net::phy::Device;
use heapless::{Vec, consts::*};

use core::cell::RefCell;

#[derive(Debug)]
pub enum NetworkError {
    NoSocket,
    ConnectionFailure,
    ReadFailure,
    WriteFailure,
}

// Structure for implementaion TcpStack interface
pub struct NetworkStack<'a, 'b, 'c> {
    sockets: RefCell<SocketSet<'a, 'b, 'c>>,
    next_port: RefCell<u16>,
    unused_handles: RefCell<Vec<SocketHandle, U16>>
}

impl<'a, 'b, 'c> NetworkStack<'a, 'b, 'c> {
    pub fn new(sockets: SocketSet<'a, 'b, 'c>) -> Self {
        let mut vec = Vec::new();
        log::info!("socket set size: {:?}", sockets.len());
        for index in 0..sockets.len() {
            vec.push(
                SocketHandle::new(index)
            ).unwrap();
        }

        Self {
            sockets: RefCell::new(sockets),
            next_port: RefCell::new(49152),
            unused_handles: RefCell::new(vec)
        }
    }

    fn get_ephemeral_port(&self) -> u16 {
        // Get the next ephemeral port
        let current_port = self.next_port.borrow().clone();

        let (next, wrap) = self.next_port.borrow().overflowing_add(1);
        *self.next_port.borrow_mut() = if wrap { 49152 } else { next };

        return current_port;
    }

    pub fn poll<DeviceT>(
        &self,
        iface: &mut EthernetInterface<DeviceT>,
        now: Instant,
    ) -> bool
    where
        DeviceT: for <'d> Device<'d>
    {
        let mut sockets = self.sockets.borrow_mut();
        sockets.polled_by(iface, now).map_or(false, |updated| updated)
    }
}

impl<'a, 'b, 'c> TcpStack for NetworkStack<'a, 'b, 'c> {
    type TcpSocket = SocketHandle;
    type Error = NetworkError;

    fn open(&self, _: Mode) -> Result<Self::TcpSocket, Self::Error> {
        match self.unused_handles.borrow_mut().pop() {
            Some(handle) => {
                // Abort any active connections on the handle.
                let mut sockets = self.sockets.borrow_mut();
                let internal_socket = sockets.get(handle);
                internal_socket.close().unwrap();

                Ok(handle)
            }
            None => {
                Err(NetworkError::NoSocket)
            },
        }
    }

    fn connect(
        &self,
        socket: Self::TcpSocket,
        remote: SocketAddr
    ) -> Result<Self::TcpSocket, Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let internal_socket = sockets.get(socket);

        match remote.ip() {
            nal::IpAddr::V4(addr) => {
                let address = {
                    let octets = addr.octets();
                    net::wire::Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
                };
                internal_socket
                    .connect((address, remote.port()), self.get_ephemeral_port())
                    .map_err(|_| NetworkError::ConnectionFailure)?;
            }
            nal::IpAddr::V6(addr) => {
                let address = {
                    let octets = addr.segments();
                    net::wire::Ipv6Address::new(
                        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                        octets[6], octets[7],
                    )
                };
                internal_socket
                    .connect((address, remote.port()), self.get_ephemeral_port())
                    .map_err(|_| NetworkError::ConnectionFailure)?;
            }
        };

        Ok(socket)
    }

    fn is_connected(
        &self,
        socket: &Self::TcpSocket
    ) -> Result<bool, Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let internal_socket = sockets.get(*socket);
        Ok(internal_socket.is_connected().unwrap())
    }

    fn write(
        &self,
        socket: &mut Self::TcpSocket,
        buffer: &[u8]
    ) -> nb::Result<usize, Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let internal_socket = sockets.get(*socket);
        internal_socket.send_slice(buffer)
            .map_err(|_| nb::Error::Other(NetworkError::WriteFailure))
    }

    fn read(
        &self,
        socket: &mut Self::TcpSocket,
        buffer: &mut [u8]
    ) -> nb::Result<usize, Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let internal_socket = sockets.get(*socket);
        internal_socket.recv_slice(buffer)
            .map_err(|_| nb::Error::Other(NetworkError::ReadFailure))
    }

    fn close(
        &self,
        socket: Self::TcpSocket
    ) -> Result<(), Self::Error> {
        let mut sockets = self.sockets.borrow_mut();
        let internal_socket = sockets.get(socket);
        internal_socket.close().unwrap();

        self.unused_handles.borrow_mut().push(socket).unwrap();
        Ok(())
    }
}