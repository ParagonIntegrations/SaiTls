use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

use p256::{EncodedPoint, ecdh::EphemeralSecret};

use core::convert::TryFrom;
use core::convert::TryInto;

use alloc::vec::Vec;

use crate::certificate::Certificate as Asn1DerCertificate;
use crate::session::DiffieHellmanPublicKey;

pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
];

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum TlsContentType {
    #[num_enum(default)]
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum AlertType {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    RecordOverflow = 22,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCA = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    InappropriateFallback = 86,
    UserCanceled = 90,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnrecognizedName = 112,
    BadCertificateStatusResponse = 113,
    UnknownPSKIdentity = 115,
    CertificateRequired = 116,
    NoApplicationProtcol = 120,
    #[num_enum(default)]
    UnknownAlert = 255
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub(crate) enum TlsVersion {
    #[num_enum(default)]
    Unknown = 0x0000,
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}

#[derive(Debug, Clone)]
pub(crate) struct TlsRepr<'a> {
    pub(crate) content_type: TlsContentType,
    pub(crate) version: TlsVersion,
    pub(crate) length: u16,
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) handshake: Option<HandshakeRepr<'a>>
}

impl<'a> TlsRepr<'a> {
    pub(crate) fn new() -> Self {
        TlsRepr {
            content_type: TlsContentType::Invalid,
            version: TlsVersion::Tls12,
            length: 0,
            payload: None,
            handshake: None,
        }
    }

    pub(crate) fn client_hello(
        mut self,
        p256_secret: &EphemeralSecret,
        x25519_secret: &x25519_dalek::EphemeralSecret,
        random: [u8; 32],
        session_id: [u8; 32]
    ) -> Self {
        self.content_type = TlsContentType::Handshake;
        self.version = TlsVersion::Tls10;
        let handshake_repr = {
            let mut repr = HandshakeRepr::new();
            repr.msg_type = HandshakeType::ClientHello;
            repr.handshake_data = HandshakeData::ClientHello({
                ClientHello::new(p256_secret, x25519_secret, random, session_id)
            });
            repr.length = repr.handshake_data.get_length().try_into().unwrap();
            repr
        };
        self.length = handshake_repr.get_length();
        self.handshake = Some(handshake_repr);
        self
    }

    pub(crate) fn server_hello(
        mut self,
        random: &'a [u8],
        session_id: &'a [u8],
        cipher_suite: CipherSuite,
        server_ecdhe_public_key: DiffieHellmanPublicKey
    ) -> Self {
        self.content_type = TlsContentType::Handshake;
        self.version = TlsVersion::Tls12;
        let handshake_repr = {
            let mut repr = HandshakeRepr::new();
            repr.msg_type = HandshakeType::ServerHello;
            repr.handshake_data = HandshakeData::ServerHello(
                {
                    ServerHello::new(
                        random,
                        session_id,
                        cipher_suite,
                        server_ecdhe_public_key
                    )
                }
            );
            repr.length = repr.handshake_data.get_length().try_into().unwrap();
            repr
        };
        self.length = handshake_repr.get_length();
        self.handshake = Some(handshake_repr);
        self
    }

    pub(crate) fn alert(mut self, alert: AlertType) -> Self {
        self.content_type = TlsContentType::Alert;
        self.version = TlsVersion::Tls12;
        let mut application_data: Vec<u8> = Vec::new();
        match alert {
            AlertType::CloseNotify | AlertType::UserCanceled => {
                application_data.push(1)
            },
            _ => {
                application_data.push(2)
            }
        };
        application_data.push(alert.try_into().unwrap());
        self.length = 2;
        self.payload = Some(application_data);
        self
    }

    // TODO: Consider replace all these boolean function
    // into a single function that returns the HandshakeType.
    pub(crate) fn is_server_hello(&self) -> bool {
        self.content_type == TlsContentType::Handshake &&
        self.payload.is_none() &&
        self.handshake.is_some() &&
        {
            if let Some(repr) = &self.handshake {
                repr.msg_type == HandshakeType::ServerHello
            } else {
                false
            }
        }
    }

    pub(crate) fn is_change_cipher_spec(&self) -> bool {
        self.content_type == TlsContentType::ChangeCipherSpec &&
        self.handshake.is_none() &&
        self.payload.is_some() &&
        {
            if let Some(data) = &self.payload {
                data[0] == 0x01 &&
                data.len() == 1
            } else {
                false
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum HandshakeType {
    #[num_enum(default)]
    Unknown = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

#[derive(Debug, Clone)]
pub(crate) struct HandshakeRepr<'a> {
    pub(crate) msg_type: HandshakeType,
    pub(crate) length: u32,
    pub(crate) handshake_data: HandshakeData<'a>,
}

impl<'a, 'b> HandshakeRepr<'a> {
    pub(self) fn new() -> Self {
        HandshakeRepr {
            msg_type: HandshakeType::Unknown,
            length: 0,
            handshake_data: HandshakeData::Uninitialized,
        }
    }

    pub(crate) fn get_length(&self) -> u16 {
        let mut length :u16 = 1;        // Handshake Type
        length += 3;                    // Length of Handshake data
        length += u16::try_from(self.handshake_data.get_length()).unwrap();
        length
    }

    pub(crate) fn get_msg_type(&self) -> HandshakeType {
        self.msg_type
    }

    pub(crate) fn get_asn1_der_certificate(&self) -> Result<&Asn1DerCertificate, ()> {
        if self.msg_type != HandshakeType::Certificate {
            return Err(())
        };
        if let HandshakeData::Certificate(
            cert
        ) = &self.handshake_data {
            Ok(cert.get_certificate(0))
        } else {
            Err(())
        }
    }

    pub(crate) fn get_all_asn1_der_certificates(&self) -> Result<Vec<&Asn1DerCertificate>, ()> {
        if self.msg_type != HandshakeType::Certificate {
            return Err(())
        };
        if let HandshakeData::Certificate(
            cert
        ) = &self.handshake_data {
            Ok(cert.get_all_certificates())
        } else {
            Err(())
        }
    }

    pub(crate) fn get_signature(&self) -> Result<(SignatureScheme, &[u8]), ()> {
        if self.msg_type != HandshakeType::CertificateVerify {
            return Err(())
        };
        if let HandshakeData::CertificateVerify(
            cert_verify
        ) = &self.handshake_data {
            Ok((cert_verify.algorithm, cert_verify.signature))
        } else {
            Err(())
        }
    }

    pub(crate) fn get_verify_data(self) -> Result<&'a [u8], ()> {
        if self.msg_type != HandshakeType::Finished {
            return Err(())
        };
        if let HandshakeData::Finished(
            fin
        ) = &self.handshake_data {
            Ok(fin.verify_data)
        } else {
            Err(())
        }
    }

    pub(crate) fn get_cert_request_extensions(&self) -> Result<&Vec<Extension>, ()> {
        if self.msg_type != HandshakeType::CertificateRequest {
            return Err(())
        };
        if let HandshakeData::CertificateRequest(req) = &self.handshake_data {
            Ok(&req.extensions)
        } else {
            Err(())
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[allow(non_camel_case_types)]
#[repr(u16)]
pub(crate) enum CipherSuite {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,
}

#[derive(Debug, Clone)]
pub(crate) struct ClientHello {
    pub(crate) version: TlsVersion,                     // Legacy: Must be Tls12 (0x0303)
    pub(crate) random: [u8; 32],
    pub(crate) session_id_length: u8,                   // Legacy: Keep it 32
    pub(crate) session_id: [u8; 32],                    // Legacy: Fill this with an unpredictable value
    pub(crate) cipher_suites_length: u16,
    pub(crate) cipher_suites: [Option<CipherSuite>; 5], // Will only realistically support 5 cipher suites
    pub(crate) compression_method_length: u8,           // Legacy: Must be 1, to contain a byte
    pub(crate) compression_methods: u8,                 // Legacy: Must be 1 byte of 0
    pub(crate) extension_length: u16,
    pub(crate) extensions: Vec<Extension>,
}

#[derive(Debug, Clone)]
pub(crate) enum HandshakeData<'a> {
    Uninitialized,
    ClientHello(ClientHello),
    ServerHello(ServerHello<'a>),
    EncryptedExtensions(EncryptedExtensions),
    Certificate(Certificate<'a>),
    CertificateVerify(CertificateVerify<'a>),
    CertificateRequest(CertificateRequest<'a>),
    Finished(Finished<'a>),
}

impl<'a> HandshakeData<'a> {
    pub(crate) fn get_length(&self) -> usize {
        match self {
            HandshakeData::ClientHello(data) => data.get_length(),
            HandshakeData::ServerHello(data) => data.get_length(),
            HandshakeData::CertificateRequest(cr) => cr.get_length(),
            _ => 0,
        }
    }
}

impl ClientHello {
    pub(self) fn new(p256_secret: &EphemeralSecret, x25519_secret: &x25519_dalek::EphemeralSecret, random: [u8; 32], session_id: [u8; 32]) -> Self {
        let mut client_hello = ClientHello {
            version: TlsVersion::Tls12,
            random,
            session_id_length: 32,
            session_id,
            cipher_suites_length: 0,
            cipher_suites: [
                Some(CipherSuite::TLS_AES_128_GCM_SHA256),
                Some(CipherSuite::TLS_AES_256_GCM_SHA384),
                Some(CipherSuite::TLS_CHACHA20_POLY1305_SHA256),
                Some(CipherSuite::TLS_AES_128_CCM_SHA256),
                None
            ],
            compression_method_length: 1,
            compression_methods: 0,
            extension_length: 0,
            extensions: Vec::new(),
        };
        
        for suite_option in client_hello.cipher_suites.iter() {
            if suite_option.is_some() {
                client_hello.cipher_suites_length += 2;
            }
        }

        client_hello.add_ch_supported_versions()
            .add_sig_algs()
            .add_client_groups_with_key_shares(p256_secret, x25519_secret)
            .finalise()
    }

    pub(crate) fn add_ch_supported_versions(mut self) -> Self {
        let length = 2;
        let mut versions = Vec::new();
        versions.push(TlsVersion::Tls13);

        let content = SupportedVersions::ClientHello {
            length,
            versions,
        };

        let extension_data = ExtensionData::SupportedVersions(content);
        let length = extension_data.get_length();
        let extension = Extension {
            extension_type: ExtensionType::SupportedVersions,
            length: length.try_into().unwrap(),
            extension_data,
        };
        
        self.extensions.push(extension);
        self
    }

    pub(crate) fn add_sig_algs(mut self) -> Self {
        let mut algorithms = Vec::new();
        {
            use SignatureScheme::*;
            algorithms.push(ecdsa_secp256r1_sha256);
            algorithms.push(ed25519);
            algorithms.push(rsa_pss_pss_sha256);
            algorithms.push(rsa_pkcs1_sha256);
            algorithms.push(rsa_pss_rsae_sha256);
            algorithms.push(rsa_pss_pss_sha384);
            algorithms.push(rsa_pkcs1_sha384);
            algorithms.push(rsa_pss_rsae_sha384);
            algorithms.push(rsa_pss_pss_sha512);
            algorithms.push(rsa_pkcs1_sha512);
            algorithms.push(rsa_pss_rsae_sha512);
        }
        let length = algorithms.len() * 2;

        let list = SignatureSchemeList {
            supported_signature_algorithms: algorithms,
            length: length.try_into().unwrap(),
        };

        let extension_data = ExtensionData::SignatureAlgorithms(list);
        let length = extension_data.get_length();
        let extension = Extension {
            extension_type: ExtensionType::SignatureAlgorithms,
            length: length.try_into().unwrap(),
            extension_data
        };

        self.extensions.push(extension);
        self
    }

    pub(crate) fn add_client_groups_with_key_shares(mut self, ecdh_secret: &EphemeralSecret, x25519_secret: &x25519_dalek::EphemeralSecret) -> Self {
        // List out all supported groups
        let mut list = Vec::new();
        list.push(NamedGroup::x25519);
        list.push(NamedGroup::secp256r1);

        // Use the list to generate all key shares and store in a vec
        let mut client_shares = Vec::new();
        let mut client_shares_length = 0;
        for named_group in list.iter() {
            let mut key_exchange = Vec::new();
            let key_share_entry = match named_group {
                NamedGroup::secp256r1 => {
                    let ecdh_public = EncodedPoint::from(ecdh_secret);
                    let x_coor = ecdh_public.x();
                    let y_coor = ecdh_public.y().unwrap();

                    key_exchange.push(0x04);                    // Legacy value
                    key_exchange.extend_from_slice(&x_coor);    
                    key_exchange.extend_from_slice(&y_coor);

                    let key_exchange_length = key_exchange.len();

                    KeyShareEntry {
                        group: *named_group,
                        length: key_exchange_length.try_into().unwrap(),
                        key_exchange
                    }
                },

                NamedGroup::x25519 => {
                    let x25519_public = x25519_dalek::PublicKey::from(x25519_secret);
                    key_exchange.extend_from_slice(x25519_public.as_bytes());

                    let key_exchange_length = key_exchange.len();

                    KeyShareEntry {
                        group: *named_group,
                        length: key_exchange_length.try_into().unwrap(),
                        key_exchange
                    }
                }
                // TODO: Implement keygen for other named groups
                _ => todo!(),
            };

            client_shares_length += key_share_entry.get_length();
            client_shares.push(key_share_entry);
        }

        // Pack up the client shares into key share
        let key_share_content = KeyShareEntryContent::KeyShareClientHello {
            length: client_shares_length.try_into().unwrap(),
            client_shares,
        };
        let extension_data = ExtensionData::KeyShareEntry(key_share_content);
        let length = extension_data.get_length();
        let key_share_extension = Extension {
            extension_type: ExtensionType::KeyShare,
            length: length.try_into().unwrap(),
            extension_data,
        };

        let length = list.len()*2;
        let group_list = NamedGroupList {
            length: length.try_into().unwrap(),
            named_group_list: list,
        };
        let extension_data = ExtensionData::NegotiatedGroups(group_list);
        let length = extension_data.get_length();
        let group_list_extension = Extension {
            extension_type: ExtensionType::SupportedGroups,
            length: length.try_into().unwrap(),
            extension_data,
        };

        self.extensions.push(group_list_extension);
        self.extensions.push(key_share_extension);
        self
    }

    pub(crate) fn finalise(mut self) -> Self {
        let mut sum = 0;
        for extension in self.extensions.iter() {
            sum += extension.get_length();
        }
        self.extension_length = sum.try_into().unwrap();
        self
    }

    pub(crate) fn get_length(&self) -> usize {
        let mut length: usize = 2;                          // TlsVersion size
        length += 32;                                       // Random size
        length += 1;                                        // Legacy session_id length size
        length += 32;                                       // Legacy session_id size
        length += 2;                                        // Cipher_suites_length size
        length += usize::try_from(self.cipher_suites_length).unwrap();
        length += 1;
        length += 1;
        length += 2;
        length += usize::try_from(self.extension_length).unwrap();
        length
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ServerHello<'a> {
    pub(crate) version: TlsVersion,
    pub(crate) random: &'a[u8],
    pub(crate) session_id_echo_length: u8,
    pub(crate) session_id_echo: &'a[u8],
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) compression_method: u8,     // Always 0
    pub(crate) extension_length: u16,
    pub(crate) extensions: Vec<Extension>,
}

impl<'a> ServerHello<'a> {
    pub(crate) fn new(
        random: &'a[u8],
        session_id_echo: &'a[u8],
        cipher_suite: CipherSuite,
        server_ecdhe_public_key: DiffieHellmanPublicKey,
    ) -> Self {
        let server_hello = Self {
            version: TlsVersion::Tls12,
            random,
            session_id_echo_length: 32,
            session_id_echo,
            cipher_suite,
            compression_method: 0,
            extension_length: 0,
            extensions: Vec::new()
        };

        server_hello.add_sh_supported_versions()
            .add_key_share(server_ecdhe_public_key)
            .finalise()
    }

    pub(crate) fn add_sh_supported_versions(mut self) -> Self {
        let supported_version_server_hello = SupportedVersions::ServerHello {
            selected_version: TlsVersion::Tls13
        };
        let extension_data = ExtensionData::SupportedVersions(
            supported_version_server_hello
        );
        let extension = Extension {
            extension_type: ExtensionType::SupportedVersions,
            length: 2,
            extension_data
        };

        // Push the extension into the vector
        self.extensions.push(extension);
        self
    }

    pub(crate) fn add_key_share(
        mut self,
        server_ecdh_public_key: DiffieHellmanPublicKey
    ) -> Self {
        let mut key_exchange: Vec<u8> = Vec::new();
        use DiffieHellmanPublicKey::*;
        let group = match server_ecdh_public_key {
            SECP256R1 { encoded_point } => {
                // Convert EncodedPoint into untagged bytes
                // In the format of x || y
                // Then put 0x04 before the bytes ( 0x04 || x || y )
                key_exchange.push(0x04);
                key_exchange.extend_from_slice(
                    &encoded_point.to_untagged_bytes().unwrap()
                );
                NamedGroup::secp256r1
            },
            X25519 { public_key } => {
                key_exchange.extend_from_slice(
                    public_key.as_bytes()
                );
                NamedGroup::x25519
            }
        };

        let length = u16::try_from(key_exchange.len()).unwrap();

        let server_share = KeyShareEntry {
            group,
            length,
            key_exchange
        };

        let key_share_entry_content = KeyShareEntryContent::KeyShareServerHello {
            server_share
        };

        let extension_data = ExtensionData::KeyShareEntry(
            key_share_entry_content
        );

        let extension = Extension {
            extension_type: ExtensionType::KeyShare,
            length: length + 2 + 2,     // 4 bytes precedes key_exchange, length(2) and group(2)
            extension_data
        };

        self.extensions.push(extension);
        self
    }

    pub(crate) fn finalise(mut self) -> Self {
        let mut sum = 0;
        for extension in self.extensions.iter() {
            // TODO: Add up the extension length
            sum += extension.get_length();
        }
        self.extension_length = sum.try_into().unwrap();
        self
    }

    pub(crate) fn get_length(&self) -> usize {
        let mut length: usize = 2;                          // TlsVersion size
        length += 32;                                       // Random size
        length += 1;                                        // Legacy session_id length size
        length += 32;                                       // Legacy session_id size
        length += 2;                                        // cipher_suites size
        length += 1;                                        // Compression method: 0
        length += 2;                                        // Extension_length
        length += usize::try_from(self.extension_length).unwrap();
        length
    }
}

#[derive(Debug, Clone)]
pub(crate) struct EncryptedExtensions {
    pub(crate) length: u16,
    pub(crate) extensions: Vec<Extension>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub(crate) enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSRTP = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PSKKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OIDFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,

    #[num_enum(default)]
    Unknown = 0xFFFF,
}

#[derive(Debug, Clone)]
pub(crate) struct Extension {
    pub(crate) extension_type: ExtensionType,
    pub(crate) length: u16,
    pub(crate) extension_data: ExtensionData,
}

impl Extension {
    pub(crate) fn get_length(&self) -> usize {
        2 + 2 + usize::try_from(self.length).unwrap()
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ExtensionData {
    SupportedVersions(SupportedVersions),
    Cookie(Cookie),
    SignatureAlgorithms(SignatureSchemeList),
    SignatureAlgorithmsCertificate(SignatureSchemeList),
    NegotiatedGroups(NamedGroupList),
    KeyShareEntry(KeyShareEntryContent),
    ServerName(ServerName),
    Unsupported,
}

impl ExtensionData {
    pub(crate) fn get_length(&self) -> usize {
        match self {
            Self::SupportedVersions(s) => s.get_length(),
            Self::SignatureAlgorithms(list) => list.get_length(),
            Self::NegotiatedGroups(list) => list.get_length(),
            Self::KeyShareEntry(entry_content) => entry_content.get_length(),

            // Implement get_length for all textension data
            _ => todo!()
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SupportedVersions {
    ClientHello {
        length: u8,
        versions: Vec<TlsVersion>,
    },
    ServerHello {
        selected_version: TlsVersion,
    }
}

impl SupportedVersions {
    pub(crate) fn get_length(&self) -> usize {
        match self {
            Self::ClientHello { length, .. } => {
                usize::try_from(*length).unwrap() + 1
            }
            Self::ServerHello { .. } => 2
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Cookie {
    length: u16,
    cookie: Vec<u8>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed488 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    /* Bad value */
    #[num_enum(default)]
    illegal = 0xFFFF,
}

#[derive(Debug, Clone)]
pub(crate) struct SignatureSchemeList {
    pub(crate) length: u16,
    pub(crate) supported_signature_algorithms: Vec<SignatureScheme>,
}

impl SignatureSchemeList {
    pub(crate) fn get_length(&self) -> usize {
        2 + usize::try_from(self.length).unwrap()
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub(crate) enum NamedGroup {
    #[num_enum(default)]
    UNKNOWN = 0x0000,

    /* Elliptic Curve Groups (ECDHE) */
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,

    /* Finite Field Groups (DHE) */
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
}

#[derive(Debug, Clone)]
pub(crate) struct NamedGroupList {
    pub(crate) length: u16,
    pub(crate) named_group_list: Vec<NamedGroup>,
}

impl NamedGroupList {
    pub(crate) fn get_length(&self) -> usize {
        usize::try_from(self.length).unwrap() + 2
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KeyShareEntry {
    pub(crate) group: NamedGroup,
    pub(crate) length: u16,
    pub(crate) key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    pub(crate) fn get_length(&self) -> usize {
        2 + 2 + usize::try_from(self.length).unwrap()
    }
}

#[derive(Debug, Clone)]
pub(crate) enum KeyShareEntryContent {
    KeyShareClientHello {
        length: u16,
        client_shares: Vec<KeyShareEntry>,
    },
    KeyShareHelloRetryRequest {
        selected_group: NamedGroup,
    },
    KeyShareServerHello {
        server_share: KeyShareEntry,
    }
}

impl KeyShareEntryContent {
    pub(crate) fn get_length(&self) -> usize {
        match self {
            Self::KeyShareClientHello { length, .. } => 2 + usize::try_from(*length).unwrap(),
            Self::KeyShareHelloRetryRequest { .. } => 2,
            Self::KeyShareServerHello { server_share } => server_share.get_length(),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
#[repr(u16)]
pub(crate) enum NameType {
    host_name = 0
}

#[derive(Debug, Clone)]
pub(crate) enum ServerNameContent {
    HostName {
        length: u16,
        host_name: Vec<u8>,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ServerName {
    name_type: NameType,
    name: ServerNameContent,
}

// Note: X.509 format is always selected unless negotiated
// This TLS implementation still yet to support certificate negotiation
#[derive(Debug, Clone)]
pub(crate) enum CertificateEntryInfo<'a> {
    // Ideally, this enum variant should never be touched
    RawPublicKey {
        ASN1_subjectPublicKeyInfo_length: u32,      // Only 24 bits
        ASN1_subjectPublicKeyInfo: &'a [u8],
    },

    X509 {
        cert_data_length: u32,                      // Only 24 bits
        cert_data: crate::certificate::Certificate<'a>,
    }
}

impl<'a> CertificateEntryInfo<'a> {
    pub(crate) fn get_certificate(&self) -> &Asn1DerCertificate {
        match self {
            CertificateEntryInfo::RawPublicKey { .. } => todo!(),
            CertificateEntryInfo::X509 {
                cert_data, ..
            } => &cert_data
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CertificateEntry<'a> {
    pub(crate) certificate_entry_info: CertificateEntryInfo<'a>,
    pub(crate) extensions_length: u16,
    pub(crate) extensions: Vec<Extension>,
}

impl<'a> CertificateEntry<'a> {
    pub(crate) fn get_certificate(&self) -> &Asn1DerCertificate {
        self.certificate_entry_info.get_certificate()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Certificate<'a> {
    pub(crate) certificate_request_context_length: u8,         // 0 length unless responding to CERT_REQUEST
    pub(crate) certificate_request_context: &'a [u8],
    pub(crate) certificate_list_length: u32,                   // Only 24 bits
    pub(crate) certificate_list: Vec<CertificateEntry<'a>>,
}

impl<'a> Certificate<'a> {
    pub(crate) fn get_certificate(&self, index: usize) -> &Asn1DerCertificate {
        self.certificate_list[index].get_certificate()
    }

    pub(crate) fn get_all_certificates(&self) -> Vec<&Asn1DerCertificate> {
        let mut certificate_vec = Vec::new();
        for cert_entry in self.certificate_list.iter() {
            certificate_vec.push(cert_entry.get_certificate())
        }
        certificate_vec
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CertificateVerify<'a> {
    pub(crate) algorithm: SignatureScheme,
    pub(crate) signature_length: u16,
    pub(crate) signature: &'a [u8],
}

#[derive(Debug, Clone)]
pub(crate) struct Finished<'a> {
    pub(crate) verify_data: &'a [u8]
}

#[derive(Debug, Clone)]
pub(crate) struct CertificateRequest<'a> {
    pub(crate) certificate_request_context_length: u8,
    pub(crate) certificate_request_context: &'a [u8],
    pub(crate) extensions_length: u16,
    pub(crate) extensions: Vec<Extension>,
}

impl<'a> CertificateRequest<'a> {
    fn get_length(&self) -> usize {
        usize::try_from(self.certificate_request_context_length).unwrap() +
        usize::try_from(self.extensions_length).unwrap() + 3
    }
}
