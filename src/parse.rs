use nom::IResult;
use nom::bytes::complete::take;
use nom::bytes::complete::tag;
use nom::bytes::complete::take_till;
use nom::combinator::complete;
use nom::combinator::opt;
use nom::sequence::preceded;
use nom::sequence::tuple;
use nom::error::ErrorKind;

use chrono::{DateTime, FixedOffset};
use heapless::{String, consts::*};

use byteorder::{ByteOrder, NetworkEndian};

use crate::tls_packet::*;

use crate::certificate::{
    Certificate                 as Asn1DerCertificate,
    Version                     as Asn1DerVersion,
    AlgorithmIdentifier         as Asn1DerAlgId,
    Validity                    as Asn1DerValidity,
    SubjectPublicKeyInfo        as Asn1DerSubjectPublicKeyInfo,
    Extensions                  as Asn1DerExtensions,
    Extension                   as Asn1DerExtension,
    ExtensionValue              as Asn1DerExtensionValue,
    PolicyInformation           as Asn1DerPolicyInformation,
    TBSCertificate              as Asn1DerTBSCertificate,
    Name                        as Asn1DerName,
    AttributeTypeAndValue       as Asn1DerAttribute,
    GeneralName                 as Asn1DerGeneralName,
    RelativeDistinguishedName   as Asn1DerRDN,
};

use crate::oid;
use crate::oid::*;

use core::convert::TryFrom;
use core::convert::TryInto;

use alloc::vec::Vec;

// Return handshake/payload slice and TLS Record
pub(crate) fn parse_tls_repr(bytes: &[u8]) -> IResult<&[u8], (&[u8], TlsRepr)> {
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

    // Store a copy of the TLS Handshake slice to return
    let repr_slice_clone = bytes;
    {
        use crate::tls_packet::TlsContentType::*;
        match repr.content_type {
            Handshake => {
                let (_, handshake) = complete(
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
    Ok((rest, (repr_slice_clone, repr)))
}

// Convert TlsInnerPlainText in RFC 8446 into Handshake
// Diff from regular handshake:
// 1. Handshake can coalesced into a larger TLS record
// 2. Content type and zero paddings at the end
// Return handshake slice for hashing
pub(crate) fn parse_inner_plaintext_for_handshake(bytes: &[u8]) -> IResult<&[u8], Vec<(&[u8], HandshakeRepr)>> {
    let mut remaining_bytes = bytes;
    let mut handshake_vec: Vec<(&[u8], HandshakeRepr)> = Vec::new();
    
    loop {
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
            return Ok((
                &[],
                handshake_vec
            ));
        }

        let (rem, handshake_repr) = parse_handshake(remaining_bytes)?;
        let handshake_slice = &remaining_bytes[..(remaining_bytes.len()-rem.len())];
        remaining_bytes = rem;
        handshake_vec.push((handshake_slice, handshake_repr));
    }
}

// Input: The entire inner plaintext including TLS record
// (record | content | content_type | zeros)
// Get the content_type of inner_plaintext
// Also get the (optional) starting index of zero paddings
pub(crate) fn get_content_type_inner_plaintext(inner_plaintext: &[u8]) -> (TlsContentType, Option<usize>) {
    // Approach from the rear, discard zeros until a nonzero byte is found
    let mut zero_padding_start_index = inner_plaintext.len();
    while (&inner_plaintext[..zero_padding_start_index]).ends_with(&[0x00]) {
        // Record wrapper takes the first 5 byte
        // Worst case scenario there must be a content type
        if zero_padding_start_index > 6 {
            zero_padding_start_index -= 1;
        } else {
            return (TlsContentType::Invalid, None);
        }
    }
    (
        TlsContentType::try_from(inner_plaintext[zero_padding_start_index-1]).unwrap(),
        if zero_padding_start_index < inner_plaintext.len() {
            Some(zero_padding_start_index)
        } else {
            None
        }
    )
}

// Turn bytes into a handshake struct
// Will return trailing bytes, if too much bytes were supplied
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
            ClientHello => {
                let (rest, data) = parse_client_hello(rest)?;
                repr.handshake_data = data;
                Ok((rest, repr))
            },
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
            CertificateRequest => {
                // Process certificate request
                let (rest, handshake_data) = parse_certificate_request(
                    rest
                )?;
                repr.handshake_data = HandshakeData::CertificateRequest(
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
            },
            CertificateVerify => {
                // Parse CertificateVerify
                let (rest, handshake_data) = parse_certificate_verify(
                    rest
                )?;
                repr.handshake_data = HandshakeData::CertificateVerify(
                    handshake_data
                );

                Ok((rest, repr))
            },
            Finished => {
                // Parse Finished, the size is determined
                // Pre-split the slice and then parse for Finished
                // i.e. check for completeness
                let (rest, possible_verify_data) = take(repr.length)(rest)?;
                let (_, handshake_data) = complete(
                    parse_finished
                )(possible_verify_data)?;

                repr.handshake_data = HandshakeData::Finished(
                    handshake_data
                );

                Ok((rest, repr))
            }
            _ => todo!()
        }
    }
}

fn parse_client_hello(bytes: &[u8]) -> IResult<&[u8], HandshakeData> {
    let version = take(2_usize);
    let random = take(32_usize);
    let session_id_length = take(1_usize);
    let (rest, (version, random, session_id_length)) = tuple((
        version, random, session_id_length
    ))(bytes)?;

    let session_id_length = session_id_length[0];
    let (rest, session_id) = take(session_id_length)(rest)?;

    let (mut rest, cipher_suites_length) = take(2_usize)(rest)?;
    let cipher_suites_length = NetworkEndian::read_u16(cipher_suites_length);
    
    let mut cipher_suites: [_; 5] = [None; 5];
    let mut index = 0;
    
    // Read cipher suites
    // Only 5 of them are supported in terms of enum availability
    // AES_CCM_8 is not an acceptable cipher suite, but can still be recorded
    for _ in 0..(cipher_suites_length/2) {
        let (rem, cipher_suite) = take(2_usize)(rest)?;

        if let Ok(cipher_suite) = CipherSuite::try_from(
            NetworkEndian::read_u16(cipher_suite)
        ) {
            cipher_suites[index] = Some(cipher_suite);
            index += 1;
        }

        rest = rem;
    }

    let (rest, compression_method_length) = take(1_usize)(rest)?;
    let compression_method_length = compression_method_length[0];
    // Can only have compression method being NULL (1 byte of 0)
    let (rest, compression_methods) = take(compression_method_length)(rest)?;
    if compression_methods != &[0] {
        return Err(nom::Err::Failure((&bytes, ErrorKind::Verify)));
    }

    let (mut rest, extension_length) = take(2_usize)(rest)?;
    let mut extension_length = NetworkEndian::read_u16(extension_length);

    let mut client_hello = ClientHello {
        version: TlsVersion::try_from(NetworkEndian::read_u16(version)).unwrap(),
        random: [0; 32],
        session_id_length,
        session_id: [0; 32],
        cipher_suites_length,
        cipher_suites,
        compression_method_length,
        compression_methods: 0,
        extension_length,
        extensions: Vec::new(),
    };

    client_hello.random.clone_from_slice(&random);
    &mut client_hello.session_id[
        32-(usize::try_from(session_id_length).unwrap())..
    ].clone_from_slice(&session_id);

    while extension_length > 0 {
        let (rem, extension) = parse_extension(rest, HandshakeType::ClientHello)?;
        rest = rem;
        extension_length -= u16::try_from(extension.get_length()).unwrap();

        client_hello.extensions.push(extension);
    }

    Ok((rest, HandshakeData::ClientHello(client_hello)))
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
    let (rest, extension_length) = take(2_usize)(bytes)?;
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

fn parse_certificate_request(bytes: &[u8]) -> IResult<&[u8], CertificateRequest> {
    let (rest, certificate_request_context_length) = take(1_usize)(bytes)?;
    let certificate_request_context_length = certificate_request_context_length[0];

    let (rest, certificate_request_context) = take(
        certificate_request_context_length
    )(rest)?;

    let (rest, extensions_length) = take(2_usize)(rest)?;
    let extensions_length = NetworkEndian::read_u16(extensions_length);
    let (rest, mut extensions_data) = take(extensions_length)(rest)?;

    let mut extensions: Vec<Extension> = Vec::new();

    while extensions_data.len() != 0 {
        let (rem, extension) = parse_extension(
            extensions_data,
            HandshakeType::CertificateRequest
        )?;
        extensions_data = rem;
        extensions.push(extension);
    }

    let certificate_request = CertificateRequest {
        certificate_request_context_length,
        certificate_request_context,
        extensions_length,
        extensions
    };

    Ok((
        rest,
        certificate_request
    ))
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

fn parse_certificate_verify(bytes: &[u8]) -> IResult<&[u8], CertificateVerify> {
    let signature_scheme = take(2_usize);
    let signature_length = take(2_usize);
    let (rest, (signature_scheme, signature_length)) = tuple((
        signature_scheme,
        signature_length
    ))(bytes)?;

    let signature_scheme = SignatureScheme::try_from(
        NetworkEndian::read_u16(signature_scheme)
    ).unwrap();
    let signature_length = NetworkEndian::read_u16(signature_length);

    // Take the signature portion out
    let (rest, signature) = take(signature_length)(rest)?;

    Ok((
        rest,
        CertificateVerify {
            algorithm: signature_scheme,
            signature_length,
            signature
        }
    ))
}

fn parse_finished(bytes: &[u8]) -> IResult<&[u8], Finished> {
    Ok((
        &[],
        Finished { verify_data: bytes }
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
        log::info!("extension type: {:?}", extension_type);
	    // TODO: Handle all mandatory extension type
        use ExtensionType::*;
        match extension_type {
            SupportedVersions => {
                match handshake_type {
                    HandshakeType::ClientHello => {
                        let (rest, versions_length) = take(1_usize)(rest)?;
                        let versions_length = versions_length[0];

                        let (rest, mut versions_slice) = take(versions_length)(rest)?;
                        let mut versions = Vec::new();

                        while versions_slice.len() != 0 {
                            let (rem, version) = take(2_usize)(versions_slice)?;

                            let tls_version = TlsVersion::try_from(
                                NetworkEndian::read_u16(version)
                            ).unwrap();
                            if tls_version != TlsVersion::Unknown {
                                versions.push(tls_version);
                            }

                            versions_slice = rem;
                        }

                        let client_supported_versions = ExtensionData::SupportedVersions(
                            crate::tls_packet::SupportedVersions::ClientHello {
                                length: versions_length,
                                versions,
                            }
                        );

                        (
                            rest,
                            client_supported_versions
                        )

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
                    _ => unreachable!()
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
                        let (rest, length) = take(2_usize)(rest)?;
                        let length = NetworkEndian::read_u16(length);
                        let (rest, mut keyshares) = take(length)(rest)?;

                        let mut client_shares = Vec::new();

                        // Read all keyshares
                        while keyshares.len() != 0 {
                        	let group = take(2_usize);
                        	let length = take(2_usize);
                        	let (rem, (group, length)) = tuple((
                        	    group, length
                        	))(keyshares)?;

                        	let mut key_share_entry = KeyShareEntry {
                        	    group: NamedGroup::try_from(
                        	        NetworkEndian::read_u16(group)
                        	    ).unwrap(),
                        	    length: NetworkEndian::read_u16(length),
                        	    key_exchange: Vec::new()
                        	};

                        	let (rem, key_exchange_slice) = take(
                        	    key_share_entry.length
                        	)(rem)?;
                        	key_share_entry.key_exchange.extend_from_slice(key_exchange_slice);

                        	client_shares.push(key_share_entry);

                        	keyshares = rem;
                        }

                        let key_share_ch = crate::tls_packet::KeyShareEntryContent::KeyShareClientHello {
                            length,
                            client_shares
                        };

                        (rest, ExtensionData::KeyShareEntry(key_share_ch))
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
            SignatureAlgorithms => {
                let (rest, supported_signature_algorithm_length) =
                    take(2_usize)(rest)?;
                let supported_signature_algorithm_length =
                    NetworkEndian::read_u16(supported_signature_algorithm_length);
                
                // Take the allocated extension bytes from rest
                let (rest, mut algorithms) = take(
                    supported_signature_algorithm_length
                )(rest)?;

                // Parse all algorithms
                let mut supported_signature_algorithms: Vec<SignatureScheme> =
                    Vec::new();
                while algorithms.len() != 0 {
                    let (rem, algorithm) = take(2_usize)(algorithms)?;
                    let sig_alg = SignatureScheme::try_from(
                        NetworkEndian::read_u16(algorithm)
                    ).unwrap();
                    algorithms = rem;
                    supported_signature_algorithms.push(sig_alg);
                }

                let signature_scheme_list = crate::tls_packet::SignatureSchemeList {
                    length: supported_signature_algorithm_length,
                    supported_signature_algorithms
                };

                (rest, ExtensionData::SignatureAlgorithms(signature_scheme_list))
            },
            _ => {
                let (rest, _) = take(length)(rest)?;
                (rest, ExtensionData::Unsupported)
            }
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

// Parse tag and length
// Return remaining bytes, tag (as byte), indicated length,
// and header (tag + length field) length
pub fn parse_asn1_der_header(bytes: &[u8]) -> IResult<&[u8], (u8, usize, usize)> {
    // Parse tag
    let (rest, tag) = take(1_usize)(bytes)?;
    // Parse length
    let (rest, length_byte) = take(1_usize)(rest)?;
    if length_byte[0] <= 0x7F {
        // Header length is 2 bytes
        // Tag: 1; Length: 1
        Ok((rest, (tag[0], length_byte[0].into(), 2)))
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
        
        // Header length:
        // Tag: 1; Length: long_form_indic (1) + size of length (length_size)
        Ok((
            rem,
            (
                tag[0],
                usize::from_be_bytes((*length_array).try_into().unwrap()),
                1 + 1 + usize::try_from(length_size).unwrap()
            )
        ))
    }
}

// Length: (return param) returns the length of the entire asn1_der_object
// Length of the value within the ASN.1 DER object = value.len()
pub fn parse_asn1_der_object(bytes: &[u8]) -> IResult<&[u8], (u8, usize, &[u8])> {
    let (rest, (tag, length, header_size)) = parse_asn1_der_header(bytes)?;
    let (rest, value) = take(length)(rest)?;
    Ok((rest, (tag, length + header_size, value)))
}

pub fn parse_asn1_der_certificate(bytes: &[u8]) -> IResult<&[u8], Asn1DerCertificate> {
    let (excluded, (_, _, rest)) = parse_asn1_der_object(bytes)?;

    // Return encoded TBS certificate in ASN1 DER
    // For convenience of validation
    let tbs_certificate_encoded = rest;

    let (_, (tbs_certificate, sig_alg, sig_value)) = complete(
        tuple((
            parse_asn1_der_tbs_certificate,
            parse_asn1_der_algorithm_identifier,
            parse_asn1_der_bit_string
        ))
    )(rest)?;

    let (_, (_, tbs_certificate_length, _)) =
        parse_asn1_der_object(tbs_certificate_encoded)?;

    Ok((
        excluded,
        Asn1DerCertificate {
            tbs_certificate,
            signature_algorithm: sig_alg,
            signature_value: sig_value,
            tbs_certificate_encoded: &tbs_certificate_encoded[0..tbs_certificate_length]
        }
    ))
}

// Parser for TBSCertificate (Sequence: 0x30)
pub fn parse_asn1_der_tbs_certificate(bytes: &[u8]) -> IResult<&[u8], Asn1DerTBSCertificate> {
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let (_, (
        version, serial_number, signature, issuer, validity, subject,
        subject_public_key_info, issuer_unique_id, subject_unique_id, extensions
    )) = complete(
        tuple((
            opt(parse_asn1_der_version),
            parse_asn1_der_serial_number,
            parse_asn1_der_algorithm_identifier,
            parse_asn1_der_name,
            parse_asn1_der_validity,
            parse_asn1_der_name,
            parse_asn1_der_subject_key_public_info,
            opt(parse_asn1_der_bit_string),
            opt(parse_asn1_der_bit_string),
            opt(parse_asn1_der_extensions)
        ))
    )(value)?;

    let version = version.unwrap_or(Asn1DerVersion::v1);
    let extensions = extensions.unwrap_or(
        Asn1DerExtensions { extensions: Vec::new() }
    );

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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0xA0
    if tag_val != 0xA0 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    // Parse the encapsulated INTEGER, force completeness
    let (_, integer) = complete(parse_asn1_der_integer)(value)?;
    // Either 0, 1, or 2, take the last byte and assert all former bytes to be 0
    Ok((rest, Asn1DerVersion::try_from(integer[0]).unwrap()))
}

// INTEGER: tag: 0x02
pub fn parse_asn1_der_integer(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x01 and the length is 1
    // The value should be 0x00 or 0xFF
    if tag_val != 0x01 || value.len() != 1 || (value[0] != 0x00 && value[0] != 0xFF) {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    Ok((rest, value[0] == 0xFF))
}

// SEQUENCE: tag: 0x30
pub fn parse_asn1_der_sequence(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    Ok((rest, value))
}

// SET: tag: 0x31
pub fn parse_asn1_der_set(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0x31
    if tag_val != 0x31 {
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0x30
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    // Parse OID, leave the rest as optionl parameters
    let (optional_param, oid) = parse_asn1_der_oid(value)?;

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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0x06
    if tag_val != 0x06 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    Ok((rest, value))
}

// Parser for Name, applicable to issuer and subject field of TBS cert.
pub fn parse_asn1_der_name(bytes: &[u8]) -> IResult<&[u8], Asn1DerName> {
    let (rest, mut rdn_sequence) = parse_asn1_der_sequence(bytes)?;
    let mut attributes_vec: Vec<Asn1DerRDN> = Vec::new();

    while rdn_sequence.len() != 0 {
        let (rem, attribute) = parse_asn1_der_relative_distinguished_name(
            rdn_sequence
        )?;
        rdn_sequence = rem;
        attributes_vec.push(attribute);
    }

    Ok((
        rest,
        Asn1DerName {
            relative_distinguished_name: attributes_vec
        }
    ))
}

// Parser for Relative Distinguished Name (RDN)
pub fn parse_asn1_der_relative_distinguished_name(bytes: &[u8]) -> IResult<&[u8], Asn1DerRDN> {
    let (rest, mut attribute_set) = parse_asn1_der_set(bytes)?;
    let mut attributes_vec: Vec<Asn1DerAttribute> = Vec::new();

    while attribute_set.len() != 0 {
        let (rem, attribute) = parse_asn1_der_attribute_type_and_value(
            attribute_set
        )?;
        attribute_set = rem;
        attributes_vec.push(attribute);
    }

    Ok((
        rest,
        Asn1DerRDN {
            type_and_attributes: attributes_vec
        }
    ))
}

// Parser for AttributeTypeAndValue struct, typically wrapped inside Name struct
pub fn parse_asn1_der_attribute_type_and_value(bytes: &[u8]) -> IResult<&[u8], Asn1DerAttribute> {
    let (rest, set) = parse_asn1_der_sequence(bytes)?;

    let (_, (oid, (tag_val, _, value))) = complete(
        tuple((
            parse_asn1_der_oid,
            parse_asn1_der_object
        ))
    )(set)?;

    // Verify that tag_val is either "PrintableString or UTF8String"
    if tag_val != 0x13 && tag_val != 0x0C && tag_val != 0x16 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }

    Ok((
        rest,
        Asn1DerAttribute {
            attribute_type: oid,
            attribute_value: core::str::from_utf8(value).unwrap()
        }
    ))
}

// Parser for Time Validity Sequence Structure (0x30)
pub fn parse_asn1_der_validity(bytes: &[u8]) -> IResult<&[u8], Asn1DerValidity> {
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
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
pub fn parse_ans1_der_time(bytes: &[u8]) -> IResult<&[u8], DateTime<FixedOffset>> {
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Handle UTCTime, Gen.Time and Invalid Tag values
    match tag_val {
        0x17 => {
            let (_, date_time) = complete(
                parse_asn1_der_utc_time
            )(value)?;
            Ok((
                rest,
                date_time
            ))
        },
        0x18 => {
            // TODO: Not implemented
            let (_, date_time) = complete(
                parse_asn1_der_generalized_time
            )(value)?;
            Ok((
                rest,
                date_time
            ))
        },
        _ => Err(nom::Err::Failure((&[], ErrorKind::Verify)))
    }
}

// Parser for UTCTime
pub fn parse_asn1_der_utc_time(bytes: &[u8]) -> IResult<&[u8], DateTime<FixedOffset>> {

    // Buffer for building string
    // Need 19 characters to store the whole UTC time,
    // and parsible by `chrono` parser
    let mut string: String<U19> = String::new();

    // Decide the appropriate century (1950 to 2049)
    let year_tag: u8 = core::str::from_utf8(&bytes[..2]).unwrap().parse().unwrap();
    if year_tag < 50 {
        string.push_str("20").unwrap();
    } else {
        string.push_str("19").unwrap();
    }

    // Take out YYMMDDhhmm first
    let (rest, first_part) = take(10_usize)(bytes)?;
    string.push_str(core::str::from_utf8(first_part).unwrap()).unwrap();
    let (rest, _) = if u8::is_ascii_digit(&rest[0]) {
        let (rest, seconds) = take(2_usize)(rest)?;
        string.push_str(core::str::from_utf8(seconds).unwrap()).unwrap();
        (rest, seconds)
    } else {
        string.push_str("00").unwrap();
        // The second parameter will not be used anymore,
        // putting `rest` is an arbitrary choice
        (rest, rest)
    };
    match rest[0] as char {
        'Z' => {
            string.push_str("+0000")
        },
        _ => {
            string.push_str(core::str::from_utf8(rest).unwrap())
        }
    }.unwrap();

    Ok((
        &[],
        DateTime::parse_from_str(
            &string, "%Y%m%d%H%M%S%z"
        ).unwrap()
    ))
}

// Parser for GeneralizedTime
pub fn parse_asn1_der_generalized_time(bytes: &[u8]) -> IResult<&[u8], DateTime<FixedOffset>> {

    // Buffer for building string
    let mut string: String<U23> = String::new();

    // Find the first non-digit byte
    let mut first_non_digit_index = 0;
    while first_non_digit_index < bytes.len() {
        if !u8::is_ascii_digit(&bytes[first_non_digit_index]) {
            break;
        }
        first_non_digit_index += 1;
    }

    string.push_str(core::str::from_utf8(
        &bytes[..first_non_digit_index]).unwrap()
    ).unwrap();

    match first_non_digit_index {
        10 => string.push_str("0000.000").unwrap(),
        12 => string.push_str("00.000").unwrap(),
        14 => string.push_str(".000").unwrap(),
        18 => {},
        _ => return Err(nom::Err::Failure((&[], ErrorKind::Verify)))
    };

    match bytes.len() - first_non_digit_index {
        // Local time, without relative time diff to UTC time
        // Assume UTC
        0 | 1 => string.push_str("+0000").unwrap(),
        5 => string.push_str(core::str::from_utf8(
            &bytes[first_non_digit_index..]).unwrap()
        ).unwrap(),
        _ => return Err(nom::Err::Failure((&[], ErrorKind::Verify)))
    };

    Ok((
        &[],
        DateTime::parse_from_str(
            &string, "%Y%m%d%H%M%S%.3f%z"
        ).unwrap()
    ))
}

// Parser for SubjectKeyPublicInfo (Sequence: 0x30)
pub fn parse_asn1_der_subject_key_public_info(bytes: &[u8]) -> IResult<&[u8], Asn1DerSubjectPublicKeyInfo> {
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val is indeed 0xA3
    if tag_val != 0xA3 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let (_, (tag_val, _, mut value)) = complete(
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
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
        oid::CERT_SUBJECTALTNAME => {
            let (_, extension_value) = complete(
                parse_asn1_der_subject_alternative_name
            )(rem_ext_data)?;
            extension_value
        },
        oid::CERT_NAME_CONSTRAINTS => {
            let (_, extension_value) = complete(
                parse_asn1_der_name_constraints
            )(rem_ext_data)?;
            extension_value
        },
        oid::CERT_POLICY_CONSTRAINTS => {
            let (_, extension_value) = complete(
                parse_asn1_der_policy_constraints
            )(rem_ext_data)?;
            extension_value
        }
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify the tag_val represents a bitstring, and it must have length 2
    // i.e. bit-padding | bit-string
    if tag_val != 0x03 || (value.len() != 2 && value.len() != 3) {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    // Erase the padded bits
    let padding = value[0];
    let usage_array: [u8; 2] = if value.len() == 2 {
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

// Parser for Subject Alternative Name
pub fn parse_asn1_der_subject_alternative_name(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (_, mut names) = complete(
        parse_asn1_der_sequence
    )(bytes)?;

    let mut general_names: Vec<Asn1DerGeneralName> = Vec::new();

    while names.len() != 0 {
        let (rest, general_name) = parse_asn1_der_general_name(names)?;

        general_names.push(general_name);
        names = rest;
    }

    Ok((
        &[],
        Asn1DerExtensionValue::SubjectAlternativeName { general_names }
    ))
}

// Parser for GeneralName
pub fn parse_asn1_der_general_name(bytes: &[u8]) -> IResult<&[u8], Asn1DerGeneralName> {
    let (rest, (tag_val, _, name_value)) = parse_asn1_der_object(bytes)?;
    let general_name = match tag_val {
        0xA0 => {   // Constructed type, contains type-id and value
            let (_, (oid, (inner_tag_val, _, value))) = complete(
                tuple((
                    parse_asn1_der_oid,
                    parse_asn1_der_object
                ))
            )(name_value)?;
            if inner_tag_val != 0xA0 {
                return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
            }
            // Further parse the value into an ASN.1 DER object
            let (_, (_, _, name_value)) = complete(
                parse_asn1_der_object
            )(value)?;
            Asn1DerGeneralName::OtherName { type_id: oid, value: name_value }
        },

        0x81 => {
            Asn1DerGeneralName::RFC822Name(name_value)
        },

        0x82 => {
            Asn1DerGeneralName::DNSName(name_value)
        },

        0x83 => {
            Asn1DerGeneralName::X400Address(name_value)
        },

        0x84 => {
            let (_, name) = complete(
                parse_asn1_der_name
            )(name_value)?;
            Asn1DerGeneralName::DirectoryName(name)
        },

        0xA5 => {
            let (_, (
                (name_assigner_tag_val, _, name_assigner),
                party_name
            )) = complete(
                tuple((
                    parse_asn1_der_object,
                    opt(parse_asn1_der_object)
                ))
            )(name_value)?;

            let general_name = if party_name.is_none() && name_assigner_tag_val == 0x81 {
                Asn1DerGeneralName::EDIPartyName {
                    name_assigner: &[],
                    party_name: name_assigner
                }
            } else if party_name.is_some() && name_assigner_tag_val == 0x80 {
                if let Some((party_name_tag_val, _, party_name_value)) = party_name {
                    if party_name_tag_val == 0x81 {
                        Asn1DerGeneralName::EDIPartyName {
                            name_assigner,
                            party_name: party_name_value
                        }
                    }
                    else {
                        return Err(nom::Err::Error((bytes, ErrorKind::Verify)))
                    }
                } else {
                    return Err(nom::Err::Error((bytes, ErrorKind::Verify)))
                }
            } else {
                return Err(nom::Err::Error((bytes, ErrorKind::Verify)))
            };

            general_name
        },

        0x86 => {
            Asn1DerGeneralName::URI(name_value)
        },
        
        0x87 => {
            Asn1DerGeneralName::IPAddress(name_value)
        },

        0x88 => {
            Asn1DerGeneralName::RegisteredID(name_value)
        },

        _ => return Err(nom::Err::Error((bytes, ErrorKind::Verify)))
    };

    Ok((rest, general_name))
}

// Parser for Name Constraints
pub fn parse_asn1_der_name_constraints(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (_, subtrees) = complete(
        parse_asn1_der_sequence
    )(bytes)?;

    // Init name constraint extension
    let mut permitted_subtrees = Vec::new();
    let mut excluded_subtrees = Vec::new();

    let (other_subtree, (mut tag_val, _, mut subtree)) = parse_asn1_der_object(subtrees)?;

    if tag_val == 0xA0 {
        while subtree.len() != 0 {
            let (rest, permitted_names) = parse_asn1_der_sequence(subtree)?;

            // Ignore the `minimum` field and `maximum` field
            // Simpily reject any certificate with these 2 field could be a solution
            let (_, general_name) = parse_asn1_der_general_name(permitted_names)?;
            permitted_subtrees.push(general_name);
            subtree = rest;
        }

        // Move on to the excluded subtrees, or exit the procedure
        if other_subtree.len() == 0 {
            return Ok((
                &[],
                Asn1DerExtensionValue::NameConstraints {
                    permitted_subtrees,
                    excluded_subtrees
                }
            ))
        } else {
            let (_, (second_tag_val, _, second_subtree)) = complete(parse_asn1_der_object)(other_subtree)?;
            tag_val = second_tag_val;
            subtree = second_subtree;
        }
    }

    if tag_val == 0xA1 {
        while subtree.len() != 0 {
            let (rest, excluded_names) = parse_asn1_der_sequence(subtree)?;

            // Ignore the `minimum` field and `maximum` field
            // Simpily reject any certificate with these 2 field could be a solution
            let (_, general_name) = parse_asn1_der_general_name(excluded_names)?;
            excluded_subtrees.push(general_name);
            subtree = rest;
        }
    }

    return Ok((
        &[],
        Asn1DerExtensionValue::NameConstraints {
            permitted_subtrees,
            excluded_subtrees
        }
    ))
}

// Parser for policy constraints
pub fn parse_asn1_der_policy_constraints(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    // Strip sequence
    let (_, constraint_seq) = complete(
        parse_asn1_der_sequence
    )(bytes)?;

    // Init policy constraints
    let mut require_explicit_policy = None;
    let mut inhibit_policy_mapping = None;

    let (rest, (mut tag_val, _, mut policy)) = parse_asn1_der_object(constraint_seq)?;
    if tag_val == 0x80 {
        let temp = if policy.len() > 1 {
            // The maximum acceptable cert chain length would probably be less than 10
            128
        } else {
            policy[0]
        };
        require_explicit_policy.replace(temp);

        if rest.len() == 0 {
            return Ok((
                &[],
                Asn1DerExtensionValue::PolicyConstraints {
                    require_explicit_policy,
                    inhibit_policy_mapping
                }
            ))
        }

        let (_, (second_tag_val, _, second_policy)) = complete(
            parse_asn1_der_object
        )(rest)?;
        tag_val = second_tag_val;
        policy = second_policy;
    }

    if tag_val == 0x81 {
        let temp = if policy.len() > 1 {
            // The maximum acceptable cert chain length would probably be less than 10
            128
        } else {
            policy[0]
        };
        inhibit_policy_mapping.replace(temp);
    }

    Ok((
        &[],
        Asn1DerExtensionValue::PolicyConstraints {
            require_explicit_policy,
            inhibit_policy_mapping
        }
    ))
}

// Parser for CertificatePolicies Extension (sequence: 0x30)
pub fn parse_asn1_der_certificate_policies(bytes: &[u8]) -> IResult<&[u8], Asn1DerExtensionValue> {
    let (rest, (tag_val, _, mut value)) = parse_asn1_der_object(bytes)?;
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify tag value
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    let (qualifier, oid) = parse_asn1_der_oid(value)?;

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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
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
    let (rest, (tag_val, _, mut value)) = parse_asn1_der_object(bytes)?;
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
    let (rest, (tag_val, _, value)) = parse_asn1_der_object(bytes)?;
    // Verify tag value
    if tag_val != 0x04 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    Ok((rest, value))
}

// Take ASN.1 DER encoded public key
// Return a slice of modulus, and a slice of exponent
// Construct numeric value by wrapping rsa::BigUint with the return values
pub fn parse_asn1_der_rsa_public_key(bytes: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    // RSA Public key is a sequence of 2 integers
    let (_, (tag_val, _, value)) = complete(parse_asn1_der_object)(bytes)?;
    // Verify tag value
    if tag_val != 0x30 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }
    let (_, (modulus, exponent)) = complete(
        tuple((
            parse_asn1_der_integer,
            parse_asn1_der_integer
        ))
    )(value)?;

    Ok((
        &[],
        (modulus, exponent)
    ))
}

/*
 *  Prasers for PSS signature algorithms parameters in certificate
 */

// Take addition parameter of PSS algorithm idenfier
// Return hash function OID
pub fn parse_rsa_ssa_pss_parameters(params: &[u8]) -> IResult<&[u8], (&[u8], usize)> {    
    // Handle the case where there is literally no optional parameter
    // Return default SHA1 OID and 20 salt length
    if params.len() == 0 {
        return Ok((&[], (ID_SHA1, 20)))
    }
    
    // Parse as RSASSA-PSS-params (Sequence: 0x30)
    let (_, rsa_ssa_params) = complete(
        parse_asn1_der_sequence
    )(params)?;

    let (_, (hash_alg, mgf_hash_alg, salt_len, _)) = complete(
        tuple((
            opt(parse_hash_algorithm),
            opt(parse_mask_gen_algorithm),
            opt(parse_salt_length),
            opt(parse_trailer_field)
        ))
    )(rsa_ssa_params)?;

    let hash_alg = hash_alg.unwrap_or(
        Asn1DerAlgId { algorithm: ID_SHA1, parameters: &[] }
    );
    let mgf_hash_alg = mgf_hash_alg.unwrap_or(
        Asn1DerAlgId { algorithm: ID_SHA1, parameters: &[] }
    );
    let salt_len = salt_len.unwrap_or(&[0x14]);

    // Verify that the hash functions listed in HashFunc and MGF are consistent
    if hash_alg.algorithm != mgf_hash_alg.algorithm {
        todo!()
    }

    // Parse encoded salt length integer into usize
    if salt_len.len() > core::mem::size_of::<usize>() {
        todo!()
    }
    let mut array_buffer: [u8; core::mem::size_of::<usize>()] = [0; core::mem::size_of::<usize>()];
    array_buffer[(core::mem::size_of::<usize>()-salt_len.len())..].clone_from_slice(salt_len);
    let salt_len = usize::from_be_bytes(array_buffer);

    Ok((
        &[],
        (
            hash_alg.algorithm,
            salt_len
        )
    ))
}

fn parse_hash_algorithm(bytes: &[u8]) -> IResult<&[u8], Asn1DerAlgId> {
    // Parse HashAlgorithm [0]
    let (rest, (tag_val, _, hash_alg)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0xA0
    if tag_val != 0xA0 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    // Parse the encapsulated algorithm identifier, force completeness
    let (_, hash_alg) = complete(parse_asn1_der_algorithm_identifier)(hash_alg)?;
    Ok((
        rest, hash_alg
    ))
}

fn parse_mask_gen_algorithm(bytes: &[u8]) -> IResult<&[u8], Asn1DerAlgId> {
    // Parse MaskGenAlgorithm [1]
    let (rest, (tag_val, _, mask_gen_alg)) = parse_asn1_der_object(bytes)?;
    // Verify the tag is indeed 0xA1
    if tag_val != 0xA1 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    // Parse the encapsulated algorithm identifier, force completeness
    let (_, mgf) = complete(parse_asn1_der_algorithm_identifier)(mask_gen_alg)?;
    // Algorithm field of mgf should always be mgf1
    if mgf.algorithm != ID_MGF1 {
        todo!()
    }
    // Parse the parameters of MGF Alg. Ident. to get hash algorithm under MGF
    let (_, mgf_hash_alg) = complete(parse_asn1_der_algorithm_identifier)(
        mgf.parameters
    )?;
    Ok((
        rest, mgf_hash_alg
    ))
}

fn parse_salt_length(bytes: &[u8]) -> IResult<&[u8], &[u8]> {
    // Parse salt length [2]
    let (rest, (tag_val, _, salt_len)) = parse_asn1_der_object(bytes)?;
    if tag_val != 0xA2 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    // Parse the encapsulated integer, force completeness
    let (_, salt_len) = complete(
        parse_asn1_der_integer
    )(salt_len)?;

    Ok((
        rest, salt_len
    ))
}

fn parse_trailer_field(bytes: &[u8]) -> IResult<&[u8], ()> {
    // Parse trailer field [3]
    let (_, (tag_val, _, trailer_field)) = complete(
        parse_asn1_der_object
    )(bytes)?;
    if tag_val != 0xA3 {
        return Err(nom::Err::Error((bytes, ErrorKind::Verify)));
    }
    // Parse the encapsulated integer, force completeness
    let (_, trailer_field) = complete(
        parse_asn1_der_integer
    )(trailer_field)?;
    // The value must be 1 stated in RFC 4055
    if trailer_field.len() < 1 || trailer_field[trailer_field.len() - 1] != 1 {
        return Err(nom::Err::Failure((&[], ErrorKind::Verify)));
    }

    Ok((
        &[], ()
    ))
}

// Parser for identifying `r` and `s` fields of ECDSA signatures
pub fn parse_ecdsa_signature(sig: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    let (_, sig_val) = complete(
        parse_asn1_der_sequence
    )(sig)?;
    complete(
        tuple((
            parse_asn1_der_integer,
            parse_asn1_der_integer
        ))
    )(sig_val)
}
