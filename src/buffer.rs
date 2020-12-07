use core::cell::RefCell;

use smoltcp::{ Result, Error };

use alloc::vec::Vec;

use byteorder::{ByteOrder, NetworkEndian};

use crate::tls_packet::*;
use crate::key::*;

// Only designed to support read or write the entire buffer
// TODO: Stricter visibility
pub struct TlsBuffer<'a> {
    buffer: &'a mut [u8],
    index: RefCell<usize>,
}

impl<'a> Into<&'a [u8]> for TlsBuffer<'a> {
    fn into(self) -> &'a [u8] {
        &self.buffer[0..self.index.into_inner()]
    }
}

impl<'a> TlsBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            index: RefCell::new(0),
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

    pub(crate) fn enqueue_tls_repr(&mut self, tls_repr: TlsRepr<'a>) -> Result<()> {
        self.write_u8(tls_repr.content_type.into())?;
        self.write_u16(tls_repr.version.into())?;
        self.write_u16(tls_repr.length)?;
        if let Some(app_data) = tls_repr.payload {
            self.write(app_data.as_slice())?;
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
            HandshakeData::ServerHello(server_hello) => {
                self.euqueue_server_hello(server_hello)
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
            if let Some(cipher_suite) = suite {
                self.write_u16((*cipher_suite).into())?;
            }
        }
        self.write_u8(client_hello.compression_method_length)?;
        self.write_u8(client_hello.compression_methods)?;
        self.write_u16(client_hello.extension_length)?;
        self.enqueue_extensions(client_hello.extensions)
    }

    fn euqueue_server_hello(&mut self, server_hello: ServerHello<'a>) -> Result<()> {
        self.write_u16(server_hello.version.into())?;
        self.write(&server_hello.random)?;
        self.write_u8(server_hello.session_id_echo_length)?;
        self.write(&server_hello.session_id_echo)?;
        self.write_u16(server_hello.cipher_suite.into())?;
        self.write_u8(server_hello.compression_method)?;
        self.write_u16(server_hello.extension_length)?;
        self.enqueue_extensions(server_hello.extensions)
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

    pub fn enqueue_hkdf_label(&mut self, hkdf_label: HkdfLabel) -> Result<()> {
        self.write_u16(hkdf_label.length)?;
        self.write_u8(hkdf_label.label_length)?;
        self.write(hkdf_label.label)?;
        self.write_u8(hkdf_label.context_length)?;
        self.write(hkdf_label.context)
    }
}

macro_rules! export_byte_order_fn {
    ($($write_fn_name: ident, $read_fn_name: ident, $data_type: ty, $data_size: literal),+) => {
        #[allow(dead_code)]
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
    write_u24,  read_u24,   u32,    3
    // write_u32,  read_u32,   u32,    4,
    // write_u48,  read_u48,   u64,    6,
    // write_u64,  read_u64,   u64,    8
);
