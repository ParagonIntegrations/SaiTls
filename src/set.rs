use smoltcp as net;

use managed::ManagedSlice;
use crate::tls::TlsSocket;
use net::socket::SocketSet;

pub struct TlsSocketSet<'a> {
    tls_sockets: ManagedSlice<'a, Option<TlsSocket<'a>>>
}

#[derive(Clone, Copy, Debug)]
pub struct TlsSocketHandle(usize);

impl<'a> TlsSocketSet<'a> {
    pub fn new<T>(tls_sockets: T) -> Self
    where
        T: Into<ManagedSlice<'a, Option<TlsSocket<'a>>>>
    {
        Self {
            tls_sockets: tls_sockets.into()
        }
    }

    pub fn add(&mut self, socket: TlsSocket<'a>) -> TlsSocketHandle
    {
        for (index, slot) in self.tls_sockets.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(socket);
                return TlsSocketHandle(index);
            }
        }

        match self.tls_sockets {
            ManagedSlice::Borrowed(_) => {
                panic!("adding a socket to a full array")
            }

            ManagedSlice::Owned(ref mut sockets) => {
                sockets.push(Some(socket));
                let index = sockets.len() - 1;
                return TlsSocketHandle(index);
            }
        }
    }

    pub fn get(&mut self, handle: TlsSocketHandle) -> &mut TlsSocket<'a> {
        self.tls_sockets[handle.0].as_mut().unwrap()
    }

    pub(crate) fn polled_by(
        &mut self,
        sockets: &mut SocketSet
    ) -> smoltcp::Result<bool>
    {
        for socket in self.tls_sockets.iter_mut() {
            if socket.is_some() {
                socket.as_mut()
                    .unwrap()
                    .update_handshake(sockets)?;
            }
        }

        Ok(true)
    }
    
}
