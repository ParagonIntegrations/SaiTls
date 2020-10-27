use nom::IResult;
use nom::bytes::complete::take;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_till;
use nom::combinator::complete;
use nom::combinator::opt;
use nom::sequence::preceded;
use nom::sequence::tuple;
use nom::error::make_error;
use nom::error::ErrorKind;
use smoltcp::Error;
use smoltcp::Result;

use byteorder::{ByteOrder, NetworkEndian, BigEndian};

use crate::tls_packet::*;

use crate::certificate::{
    Certificate             as Asn1DerCertificate,
    Version                 as Asn1DerVersion,
    AlgorithmIdentifier     as Asn1DerAlgId,
    Time                    as Asn1DerTime,
    Validity                as Asn1DerValidity,
    SubjectPublicKeyInfo    as Asn1DerSubjectPublicKeyInfo,
    Extensions              as Asn1DerExtensions,
    Extension               as Asn1DerExtension,
    ExtensionValue          as Asn1DerExtensionValue,
    PolicyInformation       as Asn1DerPolicyInformation,
    TBSCertificate          as Asn1DerTBSCertificate,
};

use core::convert::TryFrom;
use core::convert::TryInto;

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

// Convert TlsInnerPlainText in RFC 8446 into Handshake
// Diff from regular handshake:
// 1. Handshake can coalesced into a larger TLS record
// 2. Content type and zero paddings at the end
pub(crate) fn parse_inner_plaintext_for_handshake(bytes: &[u8]) -> IResult<&[u8], Vec<HandshakeRepr>> {
    let mut remaining_bytes = bytes;
    let mut handshake_vec: Vec<HandshakeRepr> = Vec::new();
    
    while true {
        // Perform check on the number of remaining bytes
        // Case 1: At most 4 bytes left, then that must be the content type of the TLS record
        //         Assert that it is indeed handshake (0x16)
        // Case 2: More than 4 byte left, then that must either be
        //      2.1: Another handshake representation
        //      2.2: Content type | Zero padding, which can be detected by 0 length
        if remaining_bytes.len() <= 4 || 
            NetworkEndian::read_u24(&remaining_bytes[1..4]) == 0 {
            complete(
                preceded(
                    tag(&[0x16]),
                    take_till(|byte| byte != 0x00)
                )
            )(remaining_bytes)?;
            return Ok((&[], handshake_vec));
        }

        let (rem, handshake_repr) = parse_handshake(remaining_bytes)?;
        remaining_bytes = rem;
        handshake_vec.push(handshake_repr);
    }

    unreachable!()
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
                // Process EE
                let (rest, handshake_data) = parse_encrypted_extensions(
                    rest
                )?;
                repr.handshake_data = HandshakeData::EncryptedExtensions(
                    handshake_data
                );

                Ok((rest, repr))
            },
            Certificate => {
                // Process Certificate
                let (rest, handshake_data) = parse_handshake_certificate(
                    rest
                )?;
                repr.handshake_data = HandshakeData::Certificate(
                    handshake_data
                );

                Ok((rest, repr))
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
        take(0_usize)
    )(rest)?;

	Ok((rest, encrypted_extensions))
}

fn parse_handshake_certificate(bytes: &[u8]) -> IResult<&[u8], Certificate> {
    let (rest, certificate_request_context_length) = take(1_usize)(bytes)?;
    let certificate_request_context_length = certificate_request_context_length[0];

    let (rest, certificate_request_context) = take(
        certificate_request_context_length
    )(rest)?;

    let (mut rest, certificate_list_length) = take(3_usize)(rest)?;
    let certificate_list_length = NetworkEndian::read_u24(certificate_list_length);

    let mut certificate_struct = Certificate {
        certificate_request_context_length,
        certificate_request_context,
        certificate_list_length,
        certificate_list: Vec::new()
    };

    let mut certificate_list_length_counter: i32 = i32::try_from(certificate_list_length).unwrap();
    while certificate_list_length_counter > 0 {
        let (rem, (certificate_entry_length, certificate_entry)) =
            parse_handshake_certificate_entry(rest)?;
        
        certificate_list_length_counter -= i32::try_from(certificate_entry_length).unwrap();
        rest = rem;
        certificate_struct.certificate_list.push(certificate_entry);
    }

    Ok((
        rest,
        certificate_struct
    ))

}

fn parse_handshake_certificate_entry(bytes: &[u8]) -> IResult<&[u8], (u32, CertificateEntry)> {
    let (rest, (cert_entry_info_size, cert_entry_info)) = 
        parse_handshake_certificate_entry_info(bytes)?;
    
    let (mut rest, extensions_length) = take(2_usize)(rest)?;
    let extensions_length = NetworkEndian::read_u16(extensions_length);

    let mut extension_vec: Vec<Extension> = Vec::new();
    let mut extension_length_counter: i32 = extensions_length.into();
    while extension_length_counter > 0 {
        let (rem, extension) = parse_extension(rest, HandshakeType::ServerHello)?;
        rest = rem;
        extension_length_counter -= i32::try_from(extension.get_length()).unwrap();

        // Todo:: Proper error
        if extension_length_counter < 0 {
            todo!()
        }

        extension_vec.push(extension);
    }

    Ok((
        rest,
        (
            u32::try_from(extensions_length).unwrap() + 2 + cert_entry_info_size,
            CertificateEntry {
                certificate_entry_info: cert_entry_info,
                extensions_length,
                extensions: extension_vec
            }
        )
    ))
}

fn parse_handshake_certificate_entry_info(bytes: &[u8]) -> IResult<&[u8], (u32, CertificateEntryInfo)> {
    // Only supports X.509 certificate
    // No negotiation for other certificate types in prior
    let (rest, cert_data_length) = take(3_usize)(bytes)?;
    let cert_data_length = NetworkEndian::read_u24(cert_data_length);

    // Take the portion of bytes indicated by cert_data_length, and parse as
    // X509 certificate.
    let (rest, cert_data) = take(cert_data_length)(rest)?;
    let (_, cert_data) = complete(
        parse_asn1_der_certificate
    )(cert_data)?;

    Ok((
        rest,
        (
            cert_data_length + 3,
            CertificateEntryInfo::X509 {
                cert_data_length,
                cert_data
            }
        )
    ))
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
        let (_, length_array) = length_array.split_at(8 - core::mem::size_of::<usize>());
        Ok((rem, (tag[0], usize::from_be_bytes((*length_array).try_into().unwrap()))))
    }
}

// TODO: Not return length
// It is quite useless when the value slice of the exact same length is returned
// i.e. `length` can be replaced by `value.len()`
pub fn parse_asn1_der_object(bytes: &[u8]) -> IResult<&[u8], (u8, usize, &[u8])> {
    let (rest, (tag, length)) = parse_asn1_der_header(bytes)?;
    let (rest, value) = take(length)(rest)?;
    Ok((rest, (tag, length, value)))
}

pub fn parse_asn1_der_certificate(bytes: &[u8]) -> IResult<&[u8], Asn1DerCertificate> {
    let (excluded, (_, _, rest)) = parse_asn1_der_object(bytes)?;
    let (_, (tbs_certificate, sig_alg, sig_value)) = complete(
        tuple((
            parse_asn1_der_tbs_certificate,
            parse_asn1_der_algorithm_identifier,
            parse_asn1_der_bit_string
        ))
    )(rest)?;
    Ok((
        excluded,
        Asn1DerCertificate {
            tbs_certificate,
            signature_algorithm: sig_alg,
            signature_value: sig_value,
        }
    ))
}

// Parser for TBSCertificate (Sequence: 0x30)
pub fn parse_asn1_der_tbs_certificate(bytes: &[u8]) -> IResult<&[u8], Asn1DerTBSCertificate> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let (_, (
        version, serial_number, signature, issuer, validity, subject,
        subject_public_key_info, issuer_unique_id, subject_unique_id, extensions
    )) = complete(
        tuple((
            parse_asn1_der_version,
            parse_asn1_der_serial_number,
            parse_asn1_der_algorithm_identifier,
            parse_asn1_der_sequence,
            parse_asn1_der_validity,
            parse_asn1_der_sequence,
            parse_asn1_der_subject_key_public_info,
            opt(parse_asn1_der_bit_string),
            opt(parse_asn1_der_bit_string),
            parse_asn1_der_extensions
        ))
    )(value)?;

    Ok((
        rest,
        Asn1DerTBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id,
            subject_unique_id,
            extensions,
        }
    ))
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
    Ok((rest, Asn1DerVersion::try_from(integer[0]).unwrap()))
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

// BIT STRING: tag: 0x03
// Assumption: No unused bits at the last byte
// Public keys are always represented in bytes
pub fn parse_asn1_der_bit_string(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x03
    if tag_val != 0x03 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    // Dump `unused_bit` field
    let (value, unused_bit_byte) = take(1_usize)(value)?;
    // Assert no unused bits, otherwise it is a malformatted key
    if unused_bit_byte[0] != 0 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    Ok((rest, value))
}

// BOOLEAN: tag: 0x01
// Length should be 1
// 0x00 -> false; 0xFF -> true
pub fn parse_asn1_der_boolean(bytes: &[u8]) -> IResult<&[u8], bool> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x01 and the length is 1
    // The value should be 0x00 or 0xFF
    if tag_val != 0x01 || length != 1 || (value[0] != 0x00 && value[0] != 0xFF) {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    Ok((rest, value[0] == 0xFF))
}

// SEQUENCE: tag: 0x30
pub fn parse_asn1_der_sequence(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x03
    if tag_val != 0x30 {
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

// Parser for Time Validity Sequence Structure (0x30)
pub fn parse_asn1_der_validity(bytes: &[u8]) -> IResult<&[u8], Asn1DerValidity> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    let (_, (not_before, not_after)) = complete(
        tuple((
            parse_ans1_der_time,
            parse_ans1_der_time
        ))
    )(value)?;
    Ok((
        rest,
        Asn1DerValidity {
            not_before,
            not_after,
        }
    ))
}

// Parser for Time Representation (0x17: UTCTime, 0x18: GeneralizedTime)
pub fn parse_ans1_der_time(bytes: &[u8]) -> IResult<&[u8], Asn1DerTime> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Handle UTCTime, Gen.Time and Invalid Tag values
    match tag_val {
        0x17 => {
            Ok((
                rest,
                Asn1DerTime::UTCTime(value)
            ))
        },
        0x18 => {
            Ok((
                rest,
                Asn1DerTime::GeneralizedTime(value)
            ))
        },
        _ => Err(nom::Err::Failure((&[], ErrorKind::Verify)))
    }
}

// Parser for SubjectKeyPublicInfo (Sequence: 0x30)
pub fn parse_asn1_der_subject_key_public_info(bytes: &[u8]) -> IResult<&[u8], Asn1DerSubjectPublicKeyInfo> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    let (_, (algorithm, subject_public_key)) = complete(
        tuple((
            parse_asn1_der_algorithm_identifier,
            parse_asn1_der_bit_string,
        ))
    )(value)?;
    Ok((
        rest,
        Asn1DerSubjectPublicKeyInfo {
            algorithm,
            subject_public_key
        }
    ))
}

// Parser for extensions (Context-specific Sequence: 0xA3, then universal Sequence: 0x30)
pub fn parse_asn1_der_extensions(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensions> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0xA3
    if tag_val != 0xA3 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let (_, (tag_val, length, mut value)) = complete(
        parse_asn1_der_object
    )(value)?;
    // Verify the tag_val is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let mut extensions = Vec::new();
    while value.len() != 0 {
        let (rem, extension) = parse_asn1_der_extension(value)?;
        value = rem;
        extensions.push(extension);
    }

    Ok((
        rest,
        Asn1DerExtensions { extensions }
    ))
}

// Parser for an extension (Sequence: 0x30)
pub fn parse_asn1_der_extension(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtension> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    // Parse an appropriate extension according to OID and critical-ness
    let (_, (oid, critical, rem_ext_data)) = complete(
        tuple((
            parse_asn1_der_oid,
            opt(parse_asn1_der_boolean),
            parse_asn1_der_octet_string
        ))
    )(value)?;

    let extension_value = match oid {
        oid::CERT_KEY_USAGE => {
            let (_, extension_value) = complete(
                parse_asn1_der_key_usage
            )(rem_ext_data)?;
            extension_value
        },
        oid::CERT_POLICIES => {
            let (_, extension_value) = complete(
                parse_asn1_der_certificate_policies
            )(rem_ext_data)?;
            extension_value
        },
        oid::CERT_BASIC_CONSTRAINTS => {
            let (_, extension_value) = complete(
                parse_asn1_der_basic_constraints
            )(rem_ext_data)?;
            extension_value
        },
        oid::CERT_EXT_KEY_USAGE => {
            let (_, extension_value) = complete(
                parse_asn1_der_extended_key_usage
            )(rem_ext_data)?;
            extension_value
        },
        oid::CERT_INHIBIT_ANY_POLICY => {
            let (_, extension_value) = complete(
                parse_inhibit_any_policy
            )(rem_ext_data)?;
            extension_value
        },
        // TODO: Parse extension value for recognized extensions
        _ => Asn1DerExtensionValue::Unrecognized
    };
    Ok((
        rest,
        Asn1DerExtension {
            extension_id: oid,
            critical: critical.map_or(false, |b| b),
            extension_value
        }
    ))
}

// Parser for KeyUsage Extension, may have bit padding
// Do not use parse_asn1_der_bit_string, that assumes no bit padding
pub fn parse_asn1_der_key_usage(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val represents a bitstring, and it must have length 2
    // i.e. bit-padding | bit-string
    if tag_val != 0x03 || (length != 2 && length != 3) {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    // Erase the padded bits
    let padding = value[0];
    let usage_array: [u8; 2] = if length == 2 {
        [value[1], 0]
    } else {
        [value[1], value[2]]
    };
    let usage = (NetworkEndian::read_u16(&usage_array) >> padding) << padding;
    Ok((
        rest,
        Asn1DerExtensionValue::KeyUsage {
            usage
        }
    ))
}

// Parser for CertificatePolicies Extension (sequence: 0x30)
pub fn parse_asn1_der_certificate_policies(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (rest, (tag_val, length, mut value)) = parse_asn1_der_object(bytes)?;
    // Verify tag value
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let mut vec: Vec<Asn1DerPolicyInformation> = Vec::new();

    while value.len() != 0 {
        let (rem, info) = parse_asn1_der_policy_information(value)?;
        value = rem;
        vec.push(info);
    }

    Ok((
        rest,
        Asn1DerExtensionValue::CertificatePolicies {
            info: vec,
        }
    ))
}

// Parser for PolicyInformation (Sequence: 0x30)
pub fn parse_asn1_der_policy_information(bytes: &[u8]) -> IResult<&[u8], Asn1DerPolicyInformation> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify tag value
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let (_, (oid, (_, _, qualifier))) = complete(
        tuple((
            parse_asn1_der_oid,
            parse_asn1_der_object
        ))
    )(value)?;

    Ok((
        rest,
        Asn1DerPolicyInformation {
            id: oid,
            qualifier
        }
    ))
}

// Parser for BasicConstraints (Sequence: 0x30)
pub fn parse_asn1_der_basic_constraints(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify tag value
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    let (_, (is_ca, path_len_constraint)) = complete(
        tuple((
            opt(parse_asn1_der_boolean),
            opt(parse_asn1_der_integer)
        ))
    )(value)?;
    let is_ca = is_ca.map_or(false, |b| b);
    let path_len_constraint = path_len_constraint.map(
        |slice| {
            if slice.len() != 1 {
                255
            } else {
                slice[0]
            }
        }
    );
    Ok((
        rest,
        Asn1DerExtensionValue::BasicConstraints {
            is_ca,
            path_len_constraint
        }
    ))
}

// Parser for Extended Key Usage Extension (Sequence: 0x30)
pub fn parse_asn1_der_extended_key_usage(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (rest, (tag_val, length, mut value)) = parse_asn1_der_object(bytes)?;
    // Verify tag value
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let mut flags: [bool; 7] = [false; 7];

    while value.len() != 0 {
        let (rem, oid_val) = parse_asn1_der_oid(value)?;
        value = rem;
        match oid_val {
            oid::ANY_EXTENDED_KEY_USAGE => flags[0] = true,
            oid::ID_KP_SERVER_AUTH => flags[1] = true,
            oid::ID_KP_CLIENT_AUTH => flags[2] = true,
            oid::ID_KP_CODE_SIGNING => flags[3] = true,
            oid::ID_KP_EMAIL_PROTECTION => flags[4] = true,
            oid::ID_KP_TIME_STAMPING => flags[5] = true,
            oid::ID_KP_OCSP_SIGNING => flags[6] = true,
            _ => {},
        }            
    }

    Ok((
        rest,
        Asn1DerExtensionValue::ExtendedKeyUsage {
            any_extended_key_usage: flags[0],
            id_kp_server_auth: flags[1],
            id_kp_client_auth: flags[2],
            id_kp_code_signing: flags[3],
            id_kp_email_protection: flags[4],
            id_kp_time_stamping: flags[5],
            id_kp_oscp_signing: flags[6],
        }
    ))
}

// Parser for inhibit anyPolicy extension (integer)
pub fn parse_inhibit_any_policy(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (rest, integer_slice) = parse_asn1_der_integer(bytes)?;
    Ok((
        rest,
        Asn1DerExtensionValue::InhibitAnyPolicy {
            skip_certs: {
                if integer_slice.len() == 1 {
                    integer_slice[0]
                } else {
                    255
                }
            }
        }
    ))
}


// Parser for octet string (tag: 0x04)
pub fn parse_asn1_der_octet_string(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, length, value)) = parse_asn1_der_object(bytes)?;
    // Verify tag value
    if tag_val != 0x04 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    Ok((rest, value))
}

mod oid {
    // Extensions
    pub const CERT_KEY_USAGE:               &'static [u8] = &[85, 29, 15];                      // 2.5.29.15
    pub const CERT_POLICIES:                &'static [u8] = &[85, 29, 32];                      // 2.5.29.32
    pub const CERT_BASIC_CONSTRAINTS:       &'static [u8] = &[85, 29, 19];                      // 2.5.29.19
    pub const CERT_EXT_KEY_USAGE:           &'static [u8] = &[85, 29, 37];                      // 2.5.29.37
    pub const CERT_INHIBIT_ANY_POLICY:      &'static [u8] = &[85, 29, 54];                      // 2.5.29.54
    // Extended Key Extensions
    pub const ANY_EXTENDED_KEY_USAGE:       &'static [u8] = &[85, 29, 37, 0];                   // 2.5.29.37.0
    pub const ID_KP_SERVER_AUTH:            &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 1];         // 1.3.6.1.5.5.7.3.1
    pub const ID_KP_CLIENT_AUTH:            &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 2];         // 1.3.6.1.5.5.7.3.2
    pub const ID_KP_CODE_SIGNING:           &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 3];         // 1.3.6.1.5.5.7.3.3
    pub const ID_KP_EMAIL_PROTECTION:       &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 4];         // 1.3.6.1.5.5.7.3.4
    pub const ID_KP_TIME_STAMPING:          &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 8];         // 1.3.6.1.5.5.7.3.8
    pub const ID_KP_OCSP_SIGNING:           &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 9];         // 1.3.6.1.5.5.7.3.9
}
