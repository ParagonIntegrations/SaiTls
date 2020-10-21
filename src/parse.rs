use nom::IResult;
use nom::bytes::complete::take;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_till;
use nom::combinator::complete;
use nom::sequence::preceded;
use nom::sequence::tuple;
use nom::error::make_error;
use nom::error::ErrorKind;
use smoltcp::Error;
use smoltcp::Result;

use byteorder::{ByteOrder, NetworkEndian, BigEndian};

use crate::tls_packet::*;
use crate::certificate::Certificate as Asn1DerCertificate;
use crate::certificate::Version as Asn1DerVersion;
use crate::certificate::AlgorithmIdentifier as Asn1DerAlgId;

use core::convert::TryFrom;
use core::convert::TryInto;

use asn1_der::{
    DerObject,
    typed::{ DerEncodable, DerDecodable },
    Asn1DerError,
};

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
	            let mut vec: Vec<u8> = Vec::new();
	            vec.extend_from_slice(bytes);
                repr.payload = Some(vec);
            },
            _ => todo!()
        }
    }
    Ok((rest, repr))
}

// TODO: Redo EE
// Not very appropriate to classify EE as proper handshake
// It may include multiple handshakes
// Solution 1: Parse handshake again -> Recursion & return type
// Solution 2: Force caller to parse in a loop -> Extra parser to handle EE
pub(crate) fn parse_handshake(bytes: &[u8]) -> IResult<&[u8], HandshakeRepr> {
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
            EncryptedExtensions => {
                // Split data into EE and the last TLS content byte
                let (tls_content_byte, ee_data) = take(repr.length)(rest)?;

                // Process TLS content byte.
                complete(
                    tag(&[0x16])
                )(tls_content_byte)?;

                // Process EE
                let (rest, handshake_data) = parse_encrypted_extensions(
                    ee_data
                )?;
                repr.handshake_data = HandshakeData::EncryptedExtensions(
                    handshake_data
                );

                // Verify that all bytes are comsumed
                complete(
                    take(0_usize)
                )(rest)?;

                Ok((&[], repr))
            }
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

// For reference: This is the structure of encrypted text
// Source: RFC 8446 Section 5.2
//
// struct {
//     opaque content[TLSPlaintext.length];
//     ContentType type;
//     uint8 zeros[length_of_padding];
// } TLSInnerPlaintext;

fn parse_encrypted_extensions(bytes: &[u8]) -> IResult<&[u8], EncryptedExtensions> {
    let (mut rest, extension_length) = take(2_usize)(bytes)?;
    let extension_length: u16 = NetworkEndian::read_u16(extension_length);
	let mut extension_length_counter: i32 = extension_length.into();
    let mut extension_vec: Vec<Extension> = Vec::new();
    
    // Split the data into "extensions" and the rest
    let (rest, mut encypted_extension_data) =
        take(usize::try_from(extension_length).unwrap())(rest)?;
    
	while extension_length_counter > 0 {
		let (rem, extension) = parse_extension(
            encypted_extension_data,
            HandshakeType::EncryptedExtensions
        )?;
		encypted_extension_data = rem;
		extension_length_counter -= i32::try_from(extension.get_length()).unwrap();

		// Todo:: Proper error
		if extension_length_counter < 0 {
			todo!()
		}

		extension_vec.push(extension);
    }

	let encrypted_extensions = EncryptedExtensions {
		length: extension_length,
		extensions: extension_vec
    };
    
    // Force completeness. The entire slice is meant to be processed.
    complete(
        preceded(
            take(0_usize),
            // There may be zeroes beyond the content_type
            // Take "0" out until no more chaining zeros are found
            take_till(|byte| byte == 0)
        )
    )(rest)?;

	Ok((rest, encrypted_extensions))
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
	    // TODO: Handle all mandatory extension types
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
            SupportedGroups => {        // NamedGroupList
                let (rest, length) = take(2_usize)(rest)?;
                let length = NetworkEndian::read_u16(length);

                // Isolate contents, for easier error handling
                let (rest, mut rem_data) = take(length)(rest)?;

                let mut named_group_extension = NamedGroupList {
                    length,
                    named_group_list: Vec::new(),
                };

                for index in 0..(length/2) {
                    let (rem, named_group) = take(2_usize)(rem_data)?;
                    rem_data = rem;
                    let named_group = NamedGroup::try_from(
                        NetworkEndian::read_u16(named_group)
                    ).unwrap();
                    named_group_extension.named_group_list.push(named_group);

                    // Assure completeness
                    if index == (length/2) {
                        complete(take(0_usize))(rem_data)?;
                    }
                }
                (
                    rest,
                    ExtensionData::NegotiatedGroups(
                        named_group_extension
                    )
                )
            }
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

pub fn parse_asn1_der_header(bytes: &[u8]) -> IResult<&[u8], (u8, usize)> {
    // Parse tag
    let (rest, tag) = take(1_usize)(bytes)?;
    // Parse length
    let (rest, length_byte) = take(1_usize)(rest)?;
    if length_byte[0] <= 0x7F {
        Ok((rest, (tag[0], length_byte[0].into())))
    } else {
        if length_byte[0] & 0x7F > core::mem::size_of::<usize>().try_into().unwrap() {
            return Err(nom::Err::Failure((length_byte, ErrorKind::TooLarge)));
        }

        let length_size = length_byte[0] & 0x7F;
        let (rem, length_slice) = take(length_size)(rest)?;
        let mut length_array: [u8; 8] = [0; 8];
        for array_index in 0..length_slice.len() {
            length_array[array_index + 8 - length_slice.len()] = length_slice[array_index];
        }
        Ok((rem, (tag[0], usize::from_be_bytes(length_array))))
    }
}

pub fn parse_asn1_der_object(bytes: &[u8]) -> IResult<&[u8], (u8, usize, &[u8])> {
    let (rest, (tag, length)) = parse_asn1_der_header(bytes)?;
    let (rest, value) = take(length)(rest)?;
    Ok((rest, (tag, length, value)))
}

pub fn parse_asn1_der_certificate(bytes: &[u8]) -> IResult<&[u8], (&[u8], &[u8], &[u8])> {
    let (_, (_, _, rest)) = parse_asn1_der_object(bytes)?;
    let (rest, (_, _, tbscertificate_slice)) = parse_asn1_der_object(rest)?;
    let (rest, (_, _, signature_alg)) = parse_asn1_der_object(rest)?;
    let (rest, (_, _, sig_val)) = parse_asn1_der_object(rest)?;
    Ok((rest, (tbscertificate_slice, signature_alg, sig_val)))
}

pub fn parse_asn1_der_tbs_certificate(bytes: &[u8]) -> IResult<&[u8], Vec<&[u8]>> {
    todo!()
}

// version: [0] EXPLICIT Version DEFAULT V1
// Version encapsulates an Integer
// i.e. context-specific, constructed, type [0] -> tag: A0
pub fn parse_asn1_der_version(bytes: &[u8]) -> IResult<&[u8], Asn1DerVersion> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0xA0
    if tag_val != 0xA0 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    // Parse the encapsulated INTEGER, force completeness
    let (_, integer) = complete(parse_asn1_der_integer)(value)?;
    // Either 0, 1, or 2, take the last byte and assert all former bytes to be 0
    let (zeroes, version_byte) = take(integer.len()-1)(integer)?;
    complete(take_till(|byte| byte != 0))(zeroes)?;
    Ok((rest, Asn1DerVersion::try_from(version_byte[0]).unwrap()))
}

// INTEGER: tag: 0x02
pub fn parse_asn1_der_integer(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x02
    if tag_val != 0x02 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    Ok((rest, value))
}

// CertificateSerialNumber: alias of INTEGER
pub fn parse_asn1_der_serial_number(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    parse_asn1_der_integer(bytes)
}

// Algorithm Identifier: Sequence -> universal, constructed, 0 (0x30)
// Encapsulates OID (alg) and optional params (params)
pub fn parse_asn1_der_algorithm_identifier(bytes: &[u8]) -> IResult<&[u8], Asn1DerAlgId> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    // Parse OID and then optionl parameters
    let (_, (oid, (_, _, optional_param))) = complete(
        tuple((
            parse_asn1_der_oid,
            parse_asn1_der_object
        ))
    )(value)?;
    Ok((
        rest,
        Asn1DerAlgId {
            algorithm: oid,
            parameters: optional_param,
        }
    ))
}

// Parser for Universal OID type (0x06)
pub fn parse_asn1_der_oid(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0x06
    if tag_val != 0x06 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    Ok((rest, value))
}

// Parser for Time Validity Structure
pub fn parse_asn1_der_validity(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    
}
