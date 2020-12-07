use smoltcp as net;

use managed::ManagedSlice;
use crate::tls::TlsSocket;
use net::phy::Device;
use net::iface::EthernetInterface;
use net::time::Instant;

pub struct TlsSocketSet<'a, 'b, 'c> {
    tls_sockets: ManagedSlice<'a, Option<TlsSocket<'a, 'b, 'c>>>
}

#[derive(Clone, Copy, Debug)]
pub struct TlsSocketHandle(usize);

impl TlsSocketHandle {
    pub(crate) fn new(index: usize) -> Self {
        Self(index)
    }
}

impl<'a, 'b, 'c> TlsSocketSet<'a, 'b, 'c> {
    pub fn new<T>(tls_sockets: T) -> Self
    where
        T: Into<ManagedSlice<'a, Option<TlsSocket<'a, 'b, 'c>>>>
    {
        Self {
            tls_sockets: tls_sockets.into()
        }
    }

    pub fn add(&mut self, socket: TlsSocket<'a, 'b, 'c>) -> TlsSocketHandle
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

    pub fn get(&mut self, handle: TlsSocketHandle) -> &mut TlsSocket<'a, 'b, 'c> {
        self.tls_sockets[handle.0].as_mut().unwrap()
    }

    pub fn len(&self) -> usize {
        self.tls_sockets.len()
    }

    pub(crate) fn polled_by<DeviceT>(
        &mut self,
        iface: &mut EthernetInterface<DeviceT>,
        now: Instant
    ) -> smoltcp::Result<bool>
    where
        DeviceT: for<'d> Device<'d>
    {
        let mut changed = false;
        for socket in self.tls_sockets.iter_mut() {
            if socket.is_some() {
                if socket.as_mut().unwrap().update_handshake(iface, now)?
                {
                    changed = true;
                }
            }
        }

        Ok(changed)
    }
    
}
