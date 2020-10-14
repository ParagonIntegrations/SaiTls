use nom::IResult;
use nom::bytes::complete::take;
use nom::combinator::complete;
use nom::sequence::tuple;
use nom::error::ErrorKind;
use smoltcp::Error;
use smoltcp::Result;

use byteorder::{ByteOrder, NetworkEndian, BigEndian};

use crate::tls_packet::*;
use core::convert::TryFrom;

use alloc::vec::Vec;

pub(crate) fn parse_tls_repr(bytes: &[u8]) -> IResult<&[u8], TlsRepr> {
    let content_type = take(1_usize);
    let version = take(2_usize);
    let length = take(2_usize);

    let (rest, (content_type, version, length)) = 
        tuple((content_type, version, length))(bytes)?;

    let mut repr = TlsRepr {
        content_type: TlsContentType::try_from(content_type[0])
            .unwrap(),

        version: TlsVersion::try_from(NetworkEndian::read_u16(version))
            .unwrap(),

        length: NetworkEndian::read_u16(length),
        payload: None,
        handshake: None,
    };
    let (rest, bytes) = take(repr.length)(rest)?;
    {
        use crate::tls_packet::TlsContentType::*;
        match repr.content_type {
            Handshake => {
                let (rest, handshake) = complete(
                    parse_handshake
                )(bytes)?;
                repr.handshake = Some(handshake);
            },
            ChangeCipherSpec | ApplicationData => {
                repr.payload = Some(bytes);
            },
            _ => todo!()
        }
    }
    Ok((rest, repr))
}

fn parse_handshake(bytes: &[u8]) -> IResult<&[u8], HandshakeRepr> {
    let handshake_type = take(1_usize);
    let length = take(3_usize);
    
    let (rest, (handshake_type, length)) =
        tuple((handshake_type, length))(bytes)?;
    
    let mut repr = HandshakeRepr {
        msg_type: HandshakeType::try_from(handshake_type[0]).unwrap(),
        length: NetworkEndian::read_u24(length),
        handshake_data: HandshakeData::Uninitialized,
    };
    {
        use crate::tls_packet::HandshakeType::*;
        match repr.msg_type {
            ServerHello => {
                let (rest, data) = parse_server_hello(rest)?;
                repr.handshake_data = data;
                Ok((rest, repr))
            },
            _ => todo!()
        }
    }
}

fn parse_server_hello(bytes: &[u8]) -> IResult<&[u8], HandshakeData> {
    let version = take(2_usize);
    let random = take(32_usize);
    let session_id_echo_length = take(1_usize);

    let (rest, (version, random, session_id_echo_length)) =
        tuple((version, random, session_id_echo_length))(bytes)?;

    let session_id_echo_length = session_id_echo_length[0];
    let (rest, session_id_echo) = take(session_id_echo_length)(rest)?;

    let cipher_suite = take(2_usize);
    let compression_method = take(1_usize);
    let extension_length = take(2_usize);
    
    let (mut rest, (cipher_suite, compression_method, extension_length)) =
        tuple((cipher_suite, compression_method, extension_length))(rest)?;
    
    let mut server_hello = ServerHello {
        version: TlsVersion::try_from(NetworkEndian::read_u16(version)).unwrap(),
        random,
        session_id_echo_length,
        session_id_echo,
        cipher_suite: CipherSuite::try_from(NetworkEndian::read_u16(cipher_suite)).unwrap(),
        compression_method: compression_method[0],
        extension_length: NetworkEndian::read_u16(extension_length),
        extensions: Vec::new(),
    };

    let mut extension_vec: Vec<Extension> = Vec::new();
    let mut extension_length: i32 = server_hello.extension_length.into();
    while extension_length > 0 {
        let (rem, extension) = parse_extension(rest, HandshakeType::ServerHello)?;
        rest = rem;
        extension_length -= i32::try_from(extension.get_length()).unwrap();

        // Todo:: Proper error
        if extension_length < 0 {
            todo!()
        }

        extension_vec.push(extension);
    }

    server_hello.extensions = extension_vec;
    Ok((rest, HandshakeData::ServerHello(server_hello)))
}

fn parse_extension(bytes: &[u8], handshake_type: HandshakeType) -> IResult<&[u8], Extension> {
    let extension_type = take(2_usize);
    let length = take(2_usize);
    
    let (rest, (extension_type, length)) =
        tuple((extension_type, length))(bytes)?;
    
    let extension_type = ExtensionType::try_from(
        NetworkEndian::read_u16(extension_type)
    ).unwrap();
    let length = NetworkEndian::read_u16(length);

    // Process extension data according to extension_type
    // TODO: Deal with HelloRetryRequest
    let (rest, extension_data) = {
        use ExtensionType::*;
        match extension_type {
            SupportedVersions => {
                match handshake_type {
                    HandshakeType::ClientHello => {
                        todo!()
                    },
                    HandshakeType::ServerHello => {
                        let (rest, selected_version) = take(2_usize)(rest)?;
                        let selected_version = TlsVersion::try_from(
                            NetworkEndian::read_u16(selected_version)
                        ).unwrap();
                        (
                            rest,
                            ExtensionData::SupportedVersions(
                                crate::tls_packet::SupportedVersions::ServerHello {
                                    selected_version
                                }
                            )
                        )
                    },
                    _ => todo!()
                }
            },
            KeyShare => {
                match handshake_type {
                    HandshakeType::ClientHello => {
                        todo!()
                    },
                    HandshakeType::ServerHello => {
                        let group = take(2_usize);
                        let length = take(2_usize);
                        let (rest, (group, length)) =
                            tuple((group, length))(rest)?;
                        let group = NamedGroup::try_from(
                            NetworkEndian::read_u16(group)
                        ).unwrap();
                        let length = NetworkEndian::read_u16(length);
                        let (rest, key_exchange_slice) = take(length)(rest)?;
                        let mut key_exchange = Vec::new();
                        key_exchange.extend_from_slice(key_exchange_slice);
                        
                        let server_share = KeyShareEntry {
                            group,
                            length,
                            key_exchange,
                        };
                        let key_share_sh = crate::tls_packet::KeyShareEntryContent::KeyShareServerHello {
                            server_share
                        };
                        (rest, ExtensionData::KeyShareEntry(key_share_sh))
                    },
                    _ => todo!()
                }
            },
            _ => todo!()
        }        
    };

    Ok((
        rest,
        Extension {
            extension_type,
            length,
            extension_data
        }
    ))
}
