use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

use generic_array::GenericArray;

use chrono::{DateTime, FixedOffset};

use crate::parse::parse_asn1_der_rsa_public_key;
use crate::parse::parse_rsa_ssa_pss_parameters;
use crate::parse::parse_asn1_der_oid;

use crate::Error as TlsError;
use crate::session::CertificatePublicKey;
use crate::oid::*;
use crate::fake_rng::FakeRandom;

use sha1::{Sha1, Digest};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use rsa::{PublicKey, RSAPublicKey, PaddingScheme, BigUint, Hash};

use p256::ecdsa::signature::{Verifier};

use alloc::vec::Vec;

use byteorder::{ByteOrder, NetworkEndian};

use core::convert::TryFrom;
use core::convert::TryInto;

#[derive(Clone)]
pub struct Certificate<'a> {
    pub tbs_certificate: TBSCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: &'a [u8],
    pub tbs_certificate_encoded: &'a [u8],
}

impl<'a> core::fmt::Debug for Certificate<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Certificate")
            .field("tbs_certificate", &self.tbs_certificate)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("signature_value", &self.signature_value)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct TBSCertificate<'a> {
    pub version: Version,
    pub serial_number: &'a [u8],
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub validity: Validity,
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    pub issuer_unique_id: Option<&'a [u8]>,
    pub subject_unique_id: Option<&'a [u8]>,
    pub extensions: Extensions<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Version {
    #[num_enum(default)]
    v1 = 0,
    v2 = 1,
    v3 = 2,
}

#[derive(Debug, Clone)]
pub struct Validity {
    pub not_before: DateTime<FixedOffset>,
    pub not_after: DateTime<FixedOffset>,
}

impl Validity {
    pub fn is_valid(&self, current_time: &DateTime<FixedOffset>) -> Result<(), TlsError> {
        match (current_time >= &self.not_before) && (current_time <= &self.not_after) {
            true => Ok(()),
            false => Err(TlsError::TimeValidityError),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Time<'a> {
    UTCTime(&'a [u8]),
    GeneralizedTime(&'a [u8]),
}

#[derive(Debug, Clone)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Extensions<'a> {
    // TODO: Give a limit to the number of policies, migrate to heapless vec
    // An arbitrary upper limit does not violate RFC5280
    pub extensions: Vec<Extension<'a>>
}

#[derive(Debug, Clone)]
pub struct Extension<'a> {
    pub extension_id: &'a [u8],
    pub critical: bool,
    pub extension_value: ExtensionValue<'a>,
}

#[derive(Debug, Clone)]
pub enum ExtensionValue<'a> {
    KeyUsage {
        // Acceptable usage of this certificate
        // Cross verify with ExtendedKeyUsage
        // MSb is bit 0
        usage: u16
    },

    CertificatePolicies {
        // Policies listed in an extension
        // Need to verify its validity
        // TODO: Give a limit to the number of policies, migrate to heapless vec
        // An arbitrary upper limit does not violate RFC5280
        info: Vec<PolicyInformation<'a>>
    },

    SubjectAlternativeName {
        general_names: Vec<GeneralName<'a>>,
    },

    BasicConstraints {
        is_ca: bool,
        path_len_constraint: Option<u8>,
    },

    NameConstraints {
        // Owns a list of acceptable/unacceptable GeneralNames
        // Maximum field should not exist, minimum field is always 0
        // Vector size of 0 equivalent to NIL
        // While it doesn't make sense to have both subtrees,
        // the RFC (RFC 5280) mandated that any subtree stated in
        // excluded subtree cannot be permitted, even if it is part of
        // the permitted subtree.
        // It is probably intentional to have OPTIONAL over CHOICE
        permitted_subtrees: Vec<GeneralName<'a>>,
        excluded_subtrees: Vec<GeneralName<'a>>,
    },

    PolicyConstraints {
        require_explicit_policy: Option<u8>,
        inhibit_policy_mapping: Option<u8>,
    },

    ExtendedKeyUsage {
        // A list of all possible extended key usage in OID
        // Cross check validity with regular KeyUsage
        any_extended_key_usage: bool,
        id_kp_server_auth: bool,
        id_kp_client_auth: bool,
        id_kp_code_signing: bool,
        id_kp_email_protection: bool,
        id_kp_time_stamping: bool,
        id_kp_oscp_signing: bool,
    },

    InhibitAnyPolicy {
        // Number of certificates in the path that may still allow AnyPolicy
        // Certificate chain size should be limited to a small number
        skip_certs: u8
    },

    // Extension data from an unsupported extension type
    Unrecognized,
}

// Embedded value might be empty (&[])
// This means a reject-all/accept-none condition
#[derive(Clone, Eq, PartialEq)]
pub enum GeneralName<'a> {
    OtherName {
        type_id: &'a [u8],
        value: &'a [u8],
    },
    RFC822Name(&'a [u8]),
    DNSName(&'a [u8]),
    X400Address(&'a [u8]),
    DirectoryName(Name<'a>),
    EDIPartyName{
        name_assigner: &'a [u8],
        party_name: &'a [u8],
    },
    URI(&'a [u8]),
    IPAddress(&'a [u8]),
    RegisteredID(&'a [u8]),
}

impl<'a> core::fmt::Debug for GeneralName<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OtherName {type_id, value} => {
                f.debug_struct("OtherName")
                    .field("type_id", type_id)
                    .field("value", value)
                    .finish()
            },
            Self::RFC822Name(name) => {
                f.debug_tuple("RFC822Name")
                    .field(&core::str::from_utf8(name).unwrap())
                    .finish()
            },
            Self::DNSName(name) => {
                f.debug_tuple("DNSName")
                    .field(&core::str::from_utf8(name).unwrap())
                    .finish()
            },
            Self::X400Address(name) => {
                f.debug_tuple("X400Address")
                    .field(&core::str::from_utf8(name).unwrap())
                    .finish()
            },
            Self::DirectoryName(name) => {
                f.debug_tuple("DirectoryName")
                    .field(name)
                    .finish()
            },
            Self::EDIPartyName {name_assigner, party_name} => {
                f.debug_struct("EDIPartyName")
                    .field("name_assigner", name_assigner)
                    .field("party_name", party_name)
                    .finish()
            },
            Self::URI(name) => {
                f.debug_tuple("URI")
                    .field(&core::str::from_utf8(name).unwrap())
                    .finish()
            },
            Self::IPAddress(name) => {
                f.debug_tuple("IPAddress")
                    .field(name)
                    .finish()
            },
            Self::RegisteredID(name) => {
                f.debug_tuple("RegisteredID")
                    .field(name)
                    .finish()
            },
        }
    }
}

// Set operation for General Name (X is a subset of Y, where X, Y are the same variant)
// Will not handle `OtherName`, `X400Address`, `EDIPartyName`, `RegisteredID`,
// as these restrictions of these variants are not suggested
impl<'a> GeneralName<'a> {
    pub fn is_subset_of(&self, other: &Self) -> bool {
        match (self, other) {
            // Special case: empty set
            // Empty set is a subset of everything
            // The caveat is that Empty set represents the wild card
            // Which means everything is part of the empty set
            // This behavior is represented in the `belongs_to()` method
            (Self::URI(self_uri), Self::URI(other_uri)) => {
                if self_uri.len() == 0 || other_uri.len() == 0 {
                    self_uri.len() == 0
                } else {
                    self_uri.ends_with(other_uri)
                }
            },
            (Self::RFC822Name(self_mail), Self::RFC822Name(other_mail)) => {
                if self_mail.len() == 0 || other_mail.len() == 0 {
                    self_mail.len() == 0
                } else {
                    self_mail.ends_with(other_mail)
                }
            },
            (Self::DNSName(self_dns), Self::DNSName(other_dns)) => {
                if self_dns.len() == 0 || other_dns.len() == 0 {
                    self_dns.len() == 0
                } else {
                    self_dns.ends_with(other_dns)
                }
            },
            (Self::IPAddress(self_ip), Self::IPAddress(other_ip)) => {
                match (self_ip.len(), other_ip.len()) {
                    // `self` is a NULL network block
                    // It is always a subset of any network block
                    (0, _) => true,

                    // IPv4 Addresses
                    (8, 8) => {
                        let mut self_ip_prefix_len = 0;
                        for index in 4..8 {
                            self_ip_prefix_len += self_ip[index].count_ones();
                        }
                        let self_ipv4_cidr = smoltcp::wire::IpCidr::new(
                            smoltcp::wire::IpAddress::v4(
                                self_ip[0], self_ip[1], self_ip[2], self_ip[3]
                            ),
                            self_ip_prefix_len.try_into().unwrap()
                        );

                        let mut other_ip_prefix_len = 0;
                        for index in 4..8 {
                            other_ip_prefix_len += other_ip[index].count_ones();
                        }
                        let other_ipv4_cidr = smoltcp::wire::IpCidr::new(
                            smoltcp::wire::IpAddress::v4(
                                other_ip[0], other_ip[1], other_ip[2], other_ip[3]
                            ),
                            other_ip_prefix_len.try_into().unwrap()
                        );

                        other_ipv4_cidr.contains_subnet(&self_ipv4_cidr)
                    },

                    // Ipv6 Addresses
                    (32, 32) => {
                        let mut self_ip_prefix_len = 0;
                        for index in 16..32 {
                            self_ip_prefix_len += self_ip[index].count_ones();
                        }
                        let self_ipv4_cidr = smoltcp::wire::IpCidr::new(
                            smoltcp::wire::IpAddress::v6(
                                NetworkEndian::read_u16(&self_ip[0..2]),
                                NetworkEndian::read_u16(&self_ip[2..4]),
                                NetworkEndian::read_u16(&self_ip[4..6]),
                                NetworkEndian::read_u16(&self_ip[6..8]),
                                NetworkEndian::read_u16(&self_ip[8..10]),
                                NetworkEndian::read_u16(&self_ip[10..12]),
                                NetworkEndian::read_u16(&self_ip[12..14]),
                                NetworkEndian::read_u16(&self_ip[14..16]),
                            ),
                            self_ip_prefix_len.try_into().unwrap()
                        );

                        let mut other_ip_prefix_len = 0;
                        for index in 16..32 {
                            other_ip_prefix_len += other_ip[index].count_ones();
                        }
                        let other_ipv4_cidr = smoltcp::wire::IpCidr::new(
                            smoltcp::wire::IpAddress::v6(
                                NetworkEndian::read_u16(&other_ip[0..2]),
                                NetworkEndian::read_u16(&other_ip[2..4]),
                                NetworkEndian::read_u16(&other_ip[4..6]),
                                NetworkEndian::read_u16(&other_ip[6..8]),
                                NetworkEndian::read_u16(&other_ip[8..10]),
                                NetworkEndian::read_u16(&other_ip[10..12]),
                                NetworkEndian::read_u16(&other_ip[12..14]),
                                NetworkEndian::read_u16(&other_ip[14..16]),
                            ),
                            other_ip_prefix_len.try_into().unwrap()
                        );

                        other_ipv4_cidr.contains_subnet(&self_ipv4_cidr)
                    },

                    (_, _) => false     // Heterogeneity, in terms of IP address type
                                        // Self IP address is not NULL
                }
            },
            (Self::DirectoryName(self_name), Self::DirectoryName(other_name)) => {
                if self_name.relative_distinguished_name.len() == 0 {
                    true    // Empty set is always a subset of other set
                } else if other_name.relative_distinguished_name.len() == 0 {
                    false   // If self is not empty, other is empty, other is a subset
                } else if self_name.relative_distinguished_name.len()
                    < other_name.relative_distinguished_name.len() {
                    false
                } else {
                    // For each RDN in other, if self has the same RDN
                    // then self is within the subtree of other
                    // Special case: therecould be no RDN in other
                    // In this case other_name is empty
                    // it should be handled in prior
                    for other_rdn in other_name.relative_distinguished_name.iter() {
                        if self_name.relative_distinguished_name.iter().find(
                            |&self_rdn| self_rdn == other_rdn
                        ).is_none() {
                            return false;
                        }
                    }
                    true
                }
            }
            _ => false                  // Heterogeneity, in terms of GeneralName variant
        }
    }

    // See if a specific name is part of the subtree
    // The subtle difference between determining subset and ownership is the empty set
    // Recall:
    // - Empty set is a subset of everything, intersection between 2 disjoint set is an empty set
    // - Empty set is also a wildcard, everything fits in a restriction with empty set
    //
    // IP address in SAN only includes the IP part, without network mask
    // This method is to make sure that IPv4 and IPv6 address can compare with
    // their corresponding CIDR address (i.e. 192.168.0.1 belongs to 192.168.0.0/24 network)
    pub fn belongs_to(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::URI(self_uri), Self::URI(other_uri)) => {
                self_uri.ends_with(other_uri)
            },
            (Self::RFC822Name(self_rfc_822), Self::RFC822Name(other_rfc_822)) => {
                self_rfc_822.ends_with(other_rfc_822)
            },
            (Self::DNSName(self_dns), Self::DNSName(other_dns)) => {
                self_dns.ends_with(other_dns)
            },

            (Self::IPAddress(san_ip), Self::IPAddress(cidr_network)) => {
                // Use smoltcp API to covert into IPv4/Ipv6 address/CIDR
                match (san_ip.len(), cidr_network.len()) {
                    // Wildcard case: CIDR is empty
                    // Everything fits into an empty set
                    (_, 0) => true,

                    // IPv4 case
                    (4, 8) => {
                        let ipv4_san_addr = smoltcp::wire::Ipv4Address::from_bytes(san_ip);
                        let ipv4_cidr = smoltcp::wire::Ipv4Cidr::from_netmask(
                            smoltcp::wire::Ipv4Address::from_bytes(
                                &cidr_network[0..4]
                            ),
                            smoltcp::wire::Ipv4Address::from_bytes(
                                &cidr_network[4..]
                            ),
                        ).unwrap();
                        ipv4_cidr.contains_addr(&ipv4_san_addr)
                    },

                    // IPv6 case
                    (16, 32) => {
                        let ipv6_san_addr = smoltcp::wire::Ipv6Address::from_bytes(san_ip);
                        let mut prefix_len = 0;
                        for index in 16..32 {
                            prefix_len += cidr_network[index].count_ones();
                        }
                        let ipv6_cidr = smoltcp::wire::Ipv6Cidr::new(
                            smoltcp::wire::Ipv6Address::from_bytes(
                                &cidr_network[0..16]
                            ),
                            prefix_len.try_into().unwrap()
                        );
                        ipv6_cidr.contains_addr(&ipv6_san_addr)
                    },

                    // Malformatted IP address/CIDR
                    _ => false,
                }
            },

            (Self::DirectoryName(self_dir_name), Self::DirectoryName(other_dir_name)) => {
                self_dir_name.belongs_to(other_dir_name)
            },

            // Unsupported variant/heterogeneous comparison
            _ => false,
        }
    }

    pub fn is_same_variant(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::URI(..), Self::URI(..))
            | (Self::RFC822Name(..), Self::RFC822Name(..))
            | (Self::DNSName(..), Self::DNSName(..))
            | (Self::IPAddress(..), Self::IPAddress(..)) => {
                true
            },
            _ => false
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyInformation<'a> {
    pub id: &'a [u8],
    pub qualifier: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: &'a [u8],
    pub parameters: &'a [u8],
}

#[derive(Debug, Clone, Eq)]
pub struct Name<'a> {
    pub relative_distinguished_name: Vec<RelativeDistinguishedName<'a>>
}

impl<'a> Name<'a> {
    pub fn belongs_to(&self, other: &Self) -> bool {
        if other.relative_distinguished_name.len() == 0 {
            true        // Wildcard
        } else if self.relative_distinguished_name.len()
            < other.relative_distinguished_name.len() {
            false
        } else {
            // For each RDN in other, self must have the same RDN
            // then self is within the subtree of other
            for other_rdn in other.relative_distinguished_name.iter() {
                if self.relative_distinguished_name.iter().find(
                    |&self_rdn| self_rdn == other_rdn
                ).is_none() {
                    return false;
                }
            }
            true
        }
    }
}

impl<'a> PartialEq for Name<'a> {
    // Equivalent operator
    // It should treat permutated name as equivalent
    fn eq(&self, other: &Self) -> bool {
        for self_name in self.relative_distinguished_name.iter() {
            if other.relative_distinguished_name.iter().find(
                |&att_type_val| att_type_val == self_name
            ).is_none() {
                return false;
            }
        }
        for other_name in other.relative_distinguished_name.iter() {
            if self.relative_distinguished_name.iter().find(
                |&att_type_val| att_type_val == other_name
            ).is_none() {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RelativeDistinguishedName<'a> {
    pub type_and_attributes: Vec<AttributeTypeAndValue<'a>>
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttributeTypeAndValue<'a> {
    pub attribute_type: &'a [u8],       // OID
    pub attribute_value: &'a str,
}

impl<'a> Certificate<'a> {
    // General return public key method
    pub fn get_cert_public_key(&self) -> Result<CertificatePublicKey, ()> {
        let public_key_info = &self.tbs_certificate.subject_public_key_info;
        let algorithm_identifier = &public_key_info.algorithm;

        // 3 possibilities: RSA_ENCRYPTION, ID_EC_PUBLIC_KEY, and EdDSA25519
        match algorithm_identifier.algorithm {
            RSA_ENCRYPTION | ID_RSASSA_PSS => {
                let (_, (modulus, exponent)) = parse_asn1_der_rsa_public_key(
                    self.tbs_certificate.subject_public_key_info.subject_public_key
                ).map_err(|_| ())?;
        
                let public_key = RSAPublicKey::new(
                    BigUint::from_bytes_be(modulus),
                    BigUint::from_bytes_be(exponent)
                ).map_err(|_| ())?;

                Ok(
                    CertificatePublicKey::RSA {
                        cert_rsa_public_key: public_key
                    }
                )
            },
            ID_EC_PUBLIC_KEY => {
                // Check the type of EC, only support secp256r1, parse as OID
                // Other types of EC repreesntation (EC param) is not be supported
                let (_, ec_oid) = parse_asn1_der_oid(algorithm_identifier.parameters)
                    .map_err(|_| ())?;
                // Will definitely NOT support custom curve
                if ec_oid != PRIME256V1 {
                    return Err(());
                }
                let p256_verify_key = p256::ecdsa::VerifyKey::from_encoded_point(
                    &p256::EncodedPoint::from_untagged_bytes(
                        GenericArray::from_slice(
                            &public_key_info.subject_public_key[1..]
                        )
                    )
                ).map_err(|_| ())?;
                Ok(
                    CertificatePublicKey::ECDSA_SECP256R1_SHA256 {
                        cert_verify_key: p256_verify_key
                    }
                )
            },
            ID_EDDSA_25519 => {
                let ed25519_public_key = ed25519_dalek::PublicKey::from_bytes(
                    public_key_info.subject_public_key
                ).map_err(|_| ())?;
                Ok(
                    CertificatePublicKey::ED25519 {
                        cert_eddsa_key: ed25519_public_key
                    }
                )
            },
            _ => Err(())
        }
    }

    // Validate signature of self-signed certificate
    // Do not be confused with TLS Certificate Verify
    pub fn validate_self_signed_signature(&self) -> Result<(), TlsError> {
        let cert_public_key = self.get_cert_public_key()
            .map_err(|_| TlsError::SignatureValidationError)?;
        self.validate_signature_with_trusted(&cert_public_key)
    }

    // Validate signature of certificate signed by some CA's public key
    // Do not be confused with TLS Certificate Verify
    pub fn validate_signature_with_trusted(
        &self,
        trusted_public_key: &CertificatePublicKey
    ) -> Result<(), TlsError>
    {
        let sig_alg = self.signature_algorithm.algorithm;

        // Prepare hash value
        match sig_alg {
            SHA1_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1));
                let hashed = Sha1::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                trusted_public_key.get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA224_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_224));
                let hashed = Sha224::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                trusted_public_key.get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA256_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
                let hashed = Sha256::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                trusted_public_key.get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA384_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_384));
                let hashed = Sha384::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                trusted_public_key.get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA512_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_512));
                let hashed = Sha512::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                trusted_public_key.get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },
            // Further process the signature algorithm of PSS before creating digests
            ID_RSASSA_PSS => {
                let (_, (hash_alg, salt_len)) = parse_rsa_ssa_pss_parameters(
                    self.signature_algorithm.parameters
                ).unwrap();
                match hash_alg {
                    ID_SHA1 => {
                        let padding = PaddingScheme::new_pss_with_salt::<Sha1, FakeRandom>(
                            FakeRandom {},
                            salt_len
                        );
                        let hashed = Sha1::digest(self.tbs_certificate_encoded);
                        let sig = self.signature_value;
                        trusted_public_key.get_rsa_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .verify(padding, &hashed, sig)
                            .map_err(|_| TlsError::SignatureValidationError)
                    },

                    ID_SHA224 => {
                        let padding = PaddingScheme::new_pss_with_salt::<Sha224, FakeRandom>(
                            FakeRandom {},
                            salt_len
                        );
                        let hashed = Sha224::digest(self.tbs_certificate_encoded);
                        let sig = self.signature_value;
                        trusted_public_key.get_rsa_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .verify(padding, &hashed, sig)
                            .map_err(|_| TlsError::SignatureValidationError)
                    },

                    ID_SHA256 => {
                        let padding = PaddingScheme::new_pss_with_salt::<Sha256, FakeRandom>(
                            FakeRandom {},
                            salt_len
                        );
                        let hashed = Sha256::digest(self.tbs_certificate_encoded);
                        let sig = self.signature_value;
                        trusted_public_key.get_rsa_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .verify(padding, &hashed, sig)
                            .map_err(|_| TlsError::SignatureValidationError)
                    },

                    ID_SHA384 => {
                        let padding = PaddingScheme::new_pss_with_salt::<Sha384, FakeRandom>(
                            FakeRandom {},
                            salt_len
                        );
                        let hashed = Sha384::digest(self.tbs_certificate_encoded);
                        let sig = self.signature_value;
                        trusted_public_key.get_rsa_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .verify(padding, &hashed, sig)
                            .map_err(|_| TlsError::SignatureValidationError)
                    },

                    ID_SHA512 => {
                        let padding = PaddingScheme::new_pss_with_salt::<Sha512, FakeRandom>(
                            FakeRandom {},
                            salt_len
                        );
                        let hashed = Sha512::digest(self.tbs_certificate_encoded);
                        let sig = self.signature_value;
                        trusted_public_key.get_rsa_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .verify(padding, &hashed, sig)
                            .map_err(|_| TlsError::SignatureValidationError)
                    },

                    // TODO: SHA3 is not on the table, implement better error rejection
                    _ => todo!()
                }
            },

            // ECDSA signature algorithm (support only `edcsa_secp256r1_sha256`)
            ECDSA_WITH_SHA256 => {
                // let (_, (r, s)) = parse_ecdsa_signature(self.signature_value)
                //     .map_err(|_| TlsError::SignatureValidationError)?;
                let sig = p256::ecdsa::Signature::from_asn1(self.signature_value)
                    .map_err(|_| TlsError::SignatureValidationError)?;
                trusted_public_key.get_ecdsa_secp256r1_sha256_verify_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(self.tbs_certificate_encoded, &sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            // Ed25519 signature algorithm
            ID_EDDSA_25519 => {
                let sig = ed25519_dalek::Signature::try_from(
                    self.signature_value
                ).map_err(|_| TlsError::SignatureValidationError)?;
                trusted_public_key.get_ed25519_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify_strict(self.tbs_certificate_encoded, &sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            _ => todo!()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidPolicyNode<'a> {
    valid_policy: &'a [u8],
    qualifier_set: &'a [u8],
    expected_policy_set: Vec<&'a [u8]>,
}

// Method to verify a prospective certificate chain
// Section 6.1, RFC 5280
pub fn verify_certificate_chain(
    certificates: Vec<Certificate>,
    current_time: DateTime<FixedOffset>,
    // `user_initial_policy_set`, it is any_policy
    trusted_issuer_name: Name,
    // trusted_signature_algorithm: crate::tls_packet::SignatureScheme,
    trusted_public_key: CertificatePublicKey,
    initial_policy_mapping_inhibit: bool,
    initial_explicit_policy: bool,
    initial_any_policy_inhibit: bool,
    initial_permitted_subtrees: Vec<GeneralName>,
    initial_excluded_subtrees: Vec<GeneralName>
) -> Result<(), TlsError> {
    // Note that if the `user_initial_policy_set` variable is set to anyPolicy,
    // Requirement: The existance of `valid_policy_tree`
    // `valid_policy_tree` is not NULL iff leaves exist at depth k when k certificates are processed
    // This leave us with a mapping of operation in the processing steps:
    // Adding nodes below leaves -> Swap the leaves with a new set of nodes as leaves
    // Pruning a branch due to the lack of new leaf -> no-op (old leaves are deallocated)
    let mut valid_policy_tree: Vec<ValidPolicyNode> = Vec::new();
    let mut initial_policy = ValidPolicyNode {
        valid_policy: crate::oid::ANY_POLICY,
        qualifier_set: &[],
        expected_policy_set: Vec::new(),
    };
    initial_policy.expected_policy_set.push(crate::oid::ANY_POLICY);
    valid_policy_tree.push(initial_policy);

    let mut permitted_subtrees = initial_permitted_subtrees;
    let mut excluded_subtrees = initial_excluded_subtrees;
    let mut explicit_policy = if initial_explicit_policy {
        0
    } else {
        certificates.len() + 1
    };
    let mut inhibit_any_policy = if initial_any_policy_inhibit {
        0
    } else {
        certificates.len() + 1
    };
    let mut policy_mapping = if initial_policy_mapping_inhibit {
        0
    } else {
        certificates.len() + 1
    };
    let mut working_public_key = trusted_public_key;
    // working_public_key_parameters, except it is compeltely unnecessary
    let mut working_issuer_name = trusted_issuer_name;
    let mut max_path_length = certificates.len();

    for cert_index in 0..certificates.len() {
        log::trace!("Processing certificate {:?}", cert_index);
        let current_certificate = &certificates[cert_index];
        current_certificate
            .validate_signature_with_trusted(&working_public_key)
            .map_err(|_| TlsError::SignatureValidationError)?;
        log::trace!("Certificate signature verified");
        current_certificate.tbs_certificate.validity
            .is_valid(&current_time)?;
        log::trace!("Certificate time is within limit");
        // Certificate Revocation List is not implemented
        // This is a certificate-in-certificate scenario
        if current_certificate.tbs_certificate.issuer != working_issuer_name {
            return Err(TlsError::CertificateIssuerMismatch);
        }
        log::trace!("Certificate name is verified");

        // (b, c) If certificate is self-issued and not the end-entity certificate,
        // verify that subject name is
        // - within one of the permitted subtrees
        // - not within any of the excluded subtrees
        //
        // and verify that each subjectAltName is
        // - within one of the permitted_subtrees for that type
        // - not within any of the excluded_subtrees for that name type
        if current_certificate.tbs_certificate.issuer != current_certificate.tbs_certificate.subject
            || (cert_index + 1) == certificates.len() {

            /*
             * Permitted subtreee block
             */
            {
                // Check if there are permitted name, and find any matching name
                let mut has_dir_name_restriction = false;
                let mut has_rfc_822_name_restriction = false;
                let mut has_dns_name_restriction = false;
                let mut has_uri_restriction = false;
                let mut has_ip_address_restriction = false;
                let mut subject_name_permitted = false;
                for permitted_dir_name in permitted_subtrees.iter() {
                    match permitted_dir_name {
                        GeneralName::DirectoryName(dir_name) => {
                            has_dir_name_restriction = true;
                            if current_certificate.tbs_certificate.subject
                                .belongs_to(dir_name)
                            {
                                subject_name_permitted = true;
                            }                  
                        },
                        GeneralName::RFC822Name(..) => {
                            has_rfc_822_name_restriction = true;
                        },
                        GeneralName::DNSName(..) => {
                            has_dns_name_restriction = true;
                        },
                        GeneralName::URI(..) => {
                            has_uri_restriction = true;
                        },
                        GeneralName::IPAddress(..) => {
                            has_ip_address_restriction = true;
                        },
                        _ => {}
                    }
                }

                // If there are restrictions in terms of permitted_subtrees,
                // while subject cannot fulfill it, reject certificate
                if has_dir_name_restriction && !subject_name_permitted {
                    return Err(TlsError::CertificateSubjectNotPermitted)
                }

                for extension in current_certificate.tbs_certificate
                    .extensions.extensions.iter()
                {
                    if let ExtensionValue::SubjectAlternativeName {
                        general_names
                    } = &extension.extension_value {
                        // For each alt. names in SAN, it is within one of the
                        // permitted_subtrees for that name type
                        for san_general_name in general_names.iter() {
                            if permitted_subtrees.iter().find(
                                |&permitted_name| {
                                    // Either the general name are identical
                                    // (for names that does not support subset operation subset),
                                    // Or it belongs to a subtree
                                    permitted_name == san_general_name ||
                                    san_general_name.belongs_to(permitted_name)
                                }
                            ).is_none() {
                                match san_general_name {
                                    GeneralName::RFC822Name(..) => if has_rfc_822_name_restriction {
                                        return Err(TlsError::CertificateSubjectNotPermitted)
                                    },
                                    GeneralName::DNSName(..) => if has_dns_name_restriction {
                                        return Err(TlsError::CertificateSubjectNotPermitted)
                                    },
                                    GeneralName::URI(..) => if has_uri_restriction {
                                        return Err(TlsError::CertificateSubjectNotPermitted)
                                    },
                                    GeneralName::IPAddress(..) => if has_ip_address_restriction {
                                        return Err(TlsError::CertificateSubjectNotPermitted)
                                    },

                                    // Other types of restrictions are not recognized
                                    _ => {},
                                }
                            }
                        }
                    }
                }
            }

            log::trace!("Subject name and SAN prmitted");

            /*
             * Excluded subtrees block
             */
            {
                // Check if there are excluded name, and find any matching name
                for excluded_dir_name in excluded_subtrees.iter() {
                    match excluded_dir_name {
                        GeneralName::DirectoryName(dir_name) => {
                            if current_certificate.tbs_certificate.subject
                                .belongs_to(dir_name)
                            {
                                return Err(TlsError::CertificateSubjectExcluded);
                            }                  
                        },
                        _ => {}
                    }
                }

                for extension in current_certificate.tbs_certificate
                    .extensions.extensions.iter()
                {
                    if let ExtensionValue::SubjectAlternativeName {
                        general_names
                    } = &extension.extension_value {
                        // For each alt. names in SAN, it is not within any excluded subtrees
                        for san_general_name in general_names.iter() {
                            if excluded_subtrees.iter().find(
                                |&excluded_name| {
                                    // Either the general name are identical
                                    // (for names that does not support subset operation subset),
                                    // Or it belongs to a subtree
                                    excluded_name == san_general_name ||
                                    san_general_name.belongs_to(excluded_name)
                                }
                            ).is_some() {
                                return Err(TlsError::CertificateSubjectExcluded);
                            }
                        }
                    }
                }
            }

            log::trace!("Subject name and SAN not excluded");
        }

        // Certificate policy, find a new set of leaves if exist
        let mut new_valid_policy_leaves: Vec<ValidPolicyNode> = Vec::new();
        let mut policy_info = None;
        for extension in current_certificate.tbs_certificate.extensions.extensions.iter() {
            if let ExtensionValue::CertificatePolicies { info } = &extension.extension_value {
                policy_info.replace(info);
                break;
            }
        }

        if policy_info.is_some() {
            let mut possible_any_policy = None;
            // For each policy P that is not anyPolicy
            for policy in policy_info.unwrap().iter() {
                if policy.id == crate::oid::ANY_POLICY {
                    possible_any_policy.replace(policy);
                    continue;
                }
    
                let mut policy_not_matched = true;
                let mut any_policy_found = false;
    
                // For each node S at depth i-1, if S expects P,
                // create a child with (P-OID, P-Q, {P-OID})
                for policy_parent in valid_policy_tree.iter() {
                    if policy_parent.expected_policy_set
                        .iter()
                        .find(|&&expected_policy| expected_policy == policy.id)
                        .is_some() {
                        let mut new_node = ValidPolicyNode {
                            valid_policy: policy.id,
                            qualifier_set: policy.qualifier,
                            expected_policy_set: Vec::new()
                        };
                        new_node.expected_policy_set.push(policy.id);
                        new_valid_policy_leaves.push(new_node);
                        policy_not_matched = false;
                    }
    
                    if policy_parent.valid_policy == ANY_POLICY {
                        any_policy_found = true;
                    }
                }
    
                // If a match is not found for this policy,
                // while an `anyPolicy' parent exists,
                // Add policy P with (P-OID, P-Q, {P-OID})
                // There is no need to add more than once
                // Only `horizontal` leaf search will be performed,
                // will only duplicate branch
                if policy_not_matched && any_policy_found {
                    let mut new_node = ValidPolicyNode {
                        valid_policy: policy.id,
                        qualifier_set: policy.qualifier,
                        expected_policy_set: Vec::new()
                    };
                    new_node.expected_policy_set.push(policy.id);
                    new_valid_policy_leaves.push(new_node);                        
                }
            }
    
            // If cert has anyPolicy, and either (inhibit_anyPolicy > 0 OR i < n)
            // AND certificate is self-issued, then forward all yet-to-be-copied
            // policies in depth i-1 to leaves with qualifier as AP-Q
            if possible_any_policy.is_some()
                && inhibit_any_policy > 0
                && cert_index + 1 < certificates.len()
            {
                log::trace!("Can add any policy to policy tree");
                for policy_parent in valid_policy_tree.iter() {
                    for expected_policy in policy_parent.expected_policy_set.iter() {
                        // If any expected policy cannot be found among the new leaves
                        // it needs to be added into the valid policies
                        if new_valid_policy_leaves.iter().find(
                            |&leaf_policy| &leaf_policy.valid_policy == expected_policy
                        ).is_none() {
                            let mut new_node = ValidPolicyNode {
                                valid_policy: expected_policy,
                                qualifier_set: possible_any_policy.unwrap().qualifier,
                                expected_policy_set: Vec::new()
                            };
                            new_node.expected_policy_set.push(expected_policy);
                            new_valid_policy_leaves.push(new_node);     
                        }
                    }
                }
            }
        }
        // Otherwise, do nothing.
        // Empty vector can represent NULL.
        
        // Replace old `valid_policy_tree` with new leaves
        // This automatically does the following things:
        // (d) prune childless branches, and
        // (e) set the entire tree to NULL, if there are no cert policies.
        valid_policy_tree = new_valid_policy_leaves;
        log::trace!("Policy tree: {:?}", valid_policy_tree);

        // (f) Verify that either:
        // -`explicit_policy` is greater than 0, OR
        // -`valid_policy_tree` is not NULL
        if explicit_policy == 0 && valid_policy_tree.len() == 0 {
            return Err(TlsError::CertificatePolicyError);
        }

        // Prepare for the next certificate (towards end cert)
        // Policy mapping is not handled
        if cert_index + 1 == certificates.len() {
            return wrap_up_verification(
                current_certificate,
                explicit_policy,
                &valid_policy_tree
            );
        }

        // (c, d, e, f) Re-assign `working_issuer_name` and `working_public_key`
        // working_public_key already includes the algorithm of the key
        working_issuer_name = current_certificate.tbs_certificate.subject.clone();
        working_public_key = current_certificate.get_cert_public_key()
            .map_err(|_| TlsError::SignatureValidationError)?;
        // Only default pre-set signature algorithms are used.
        // Parameter will never be relavent

        // Counter updates, (l) verification for non-self-issued certs
        // (h) If certificate is not self-issued, decrement all counters if non-zero
        if current_certificate.tbs_certificate.issuer != current_certificate.tbs_certificate.subject {
            explicit_policy -= 1;
            policy_mapping -= 1;
            inhibit_any_policy -= 1;

            if max_path_length == 0 {
                return Err(TlsError::CertificateVersionError);
            } else {
                max_path_length -= 1;
            }
        }

        // Ensure that the certificate is v3
        if current_certificate.tbs_certificate.version != Version::v3 {
            return Err(TlsError::CertificateVersionError);
        }

        // (g) Permitted/Excluded subtrees operations
        for extension in current_certificate.tbs_certificate.extensions.extensions.iter() {
            if let ExtensionValue::NameConstraints {
                permitted_subtrees: certificate_permitted_subtrees,
                excluded_subtrees: certificate_excluded_subtrees
            } = &extension.extension_value {
                if certificate_permitted_subtrees.len() != 0 {
                    get_subtree_intersection(
                        &mut permitted_subtrees,
                        certificate_permitted_subtrees
                    );
                }
                if certificate_excluded_subtrees.len() != 0 {
                    get_subtree_union(
                        &mut excluded_subtrees,
                        certificate_excluded_subtrees
                    );
                }
            }

            // (i) If policyConstraint extension is found, modify
            // - explicit_policy, and/or
            // - policy_mapping
            if let ExtensionValue::PolicyConstraints {
                require_explicit_policy,
                inhibit_policy_mapping,
            } = &extension.extension_value {
                if require_explicit_policy.is_some() {
                    if usize::from(require_explicit_policy.unwrap()) < explicit_policy {
                        explicit_policy = require_explicit_policy.unwrap().into();
                    }
                }
                if inhibit_policy_mapping.is_some() {
                    if usize::from(inhibit_policy_mapping.unwrap()) < policy_mapping {
                        policy_mapping = inhibit_policy_mapping.unwrap().into();
                    }
                }
            }

            // (j) Reduce inhibit_anyPolicy to that stated in the certificate
            if let ExtensionValue::InhibitAnyPolicy {
                skip_certs
            } = &extension.extension_value {
                if usize::from(*skip_certs) < inhibit_any_policy {
                    inhibit_any_policy = (*skip_certs).into();
                }
            }

            // (m) Verify that there is a BasicConstraint extension,
            // with cA set to true
            if let ExtensionValue::BasicConstraints {
                is_ca,
                path_len_constraint
            } = &extension.extension_value {
                if !is_ca {
                    return Err(TlsError::CertificateVersionError);
                }
                if path_len_constraint.is_some() {
                    if path_len_constraint.unwrap() < max_path_length as u8 {
                        max_path_length = path_len_constraint.unwrap().into();
                    }
                }
            }

            // (n) If key usage extension is found, keyCertSignbit must be set
            if let ExtensionValue::KeyUsage {
                usage
            } = &extension.extension_value {
                if usage & 0x0020 == 0 {
                    return Err(TlsError::CertificateVersionError);
                }
            }
        }
    }

    Ok(())
}

fn wrap_up_verification(
    end_cert: &Certificate,
    mut explicit_policy: usize,
    valid_policy_tree: &Vec<ValidPolicyNode>
) -> Result<(), TlsError> {

    // (a) Decrement explicit_policy
    if explicit_policy != 0 {
        explicit_policy -= 1;
    }

    for extension in end_cert.tbs_certificate.extensions.extensions.iter() {
        // (b) If there is policy constraint extension, and
        // require_explicit_policy is 0, set explicit_policy_state to be 0
        if let ExtensionValue::PolicyConstraints {
            require_explicit_policy,
            ..
        } = &extension.extension_value {
            if require_explicit_policy.is_some() {
                if require_explicit_policy.unwrap() == 0 {
                    explicit_policy = 0;
                }
            }
        }
    }

    // (c) Instantiate cert key again, but only for returning to other procedure
    // Getting it directly from certificate when needs to

    // (d, e, f) Will not work with customized algorithm
    // Only TLS signature algorithm will be supported

    // (e) `initial_policy_set` is hardwired to any-policy
    // The intersection is the entire valid_policy_tree (case II, section 6.1.4)
    if explicit_policy > 0 || valid_policy_tree.len() != 0 {
        Ok(())
    } else {
        Err(TlsError::CertificatePolicyError)
    }

}

// Mutate state_subtree to get the intersection
fn get_subtree_intersection<'a>(
    state_subtree: &mut Vec<GeneralName<'a>>,
    cert_subtree: &Vec<GeneralName<'a>>
) {
    // 1. Determine the variants that need to be preserved (i.e. body-count)
    // This is to preserve general names that does not have any matching variant
    // Intersecting or unioning onceself return the input value (by identity law)
    let mut has_self_uri_tree = false;
    let mut has_other_uri_tree = false;
    let mut has_self_rfc_822_name_tree = false;
    let mut has_other_rfc_822_name_tree = false;
    let mut has_self_dns_name_tree = false;
    let mut has_other_dns_name_tree = false;
    let mut has_self_ipv4_address_tree = false;
    let mut has_other_ipv4_address_tree = false;
    let mut has_self_ipv6_address_tree = false;
    let mut has_other_ipv6_address_tree = false;
    let mut has_self_directory_name = false;
    let mut has_other_directory_name = false;

    for general_name in state_subtree.iter() {
        match general_name {
            GeneralName::URI(..) => has_self_uri_tree = true,
            GeneralName::RFC822Name(..) => has_self_rfc_822_name_tree = true,
            GeneralName::DNSName(..) => has_self_dns_name_tree = true,
            GeneralName::IPAddress(self_ip) => {
                if self_ip.len() == 8 || self_ip.len() == 0 {
                    has_self_ipv4_address_tree = true;
                }
                if self_ip.len() == 32 || self_ip.len() == 0 {
                    has_self_ipv6_address_tree = true;
                }
            },
            GeneralName::DirectoryName(..) => has_self_directory_name = true,
            // Other general_name variants should not appear in this subtree
            _ => {},
        }
    }

    for general_name in cert_subtree.iter() {
        match general_name {
            GeneralName::URI(..) => has_other_uri_tree = true,
            GeneralName::RFC822Name(..) => has_other_rfc_822_name_tree = true,
            GeneralName::DNSName(..) => has_other_dns_name_tree = true,
            GeneralName::IPAddress(other_ip) => {
                if other_ip.len() == 8 || other_ip.len() == 0 {
                    has_other_ipv4_address_tree = true;
                }
                if other_ip.len() == 32 || other_ip.len() == 0 {
                    has_other_ipv6_address_tree = true;
                }
            },
            GeneralName::DirectoryName(..) => has_other_directory_name = true,
            // Other general_name variants should not appear in this subtree
            _ => {},
        }
    }

    // 2. Preserve subtrees that fit into the variants
    let mut preserved_subtrees: Vec<GeneralName> = Vec::new();

    for general_name in state_subtree.iter() {
        match general_name {
            GeneralName::URI(..) => {
                if !has_other_uri_tree {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::RFC822Name(..) => {
                if !has_other_rfc_822_name_tree {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::DNSName(..) => {
                if !has_other_dns_name_tree {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::IPAddress(ip) => {
                if !has_other_ipv4_address_tree && ip.len() == 8 {
                    preserved_subtrees.push((*general_name).clone());
                }
                else if !has_other_ipv6_address_tree && ip.len() == 32 {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::DirectoryName(..) => {
                if !has_other_directory_name {
                    preserved_subtrees.push((*general_name).clone());
                }
            }
            // Other general_name variants should not appear in this subtree
            _ => {},
        }
    }

    for general_name in cert_subtree.iter() {
        match general_name {
            GeneralName::URI(..) => {
                if !has_self_uri_tree {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::RFC822Name(..) => {
                if !has_self_rfc_822_name_tree {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::DNSName(..) => {
                if !has_self_dns_name_tree {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::IPAddress(ip) => {
                if !has_self_ipv4_address_tree && ip.len() == 8 {
                    preserved_subtrees.push((*general_name).clone());
                }
                else if !has_self_ipv6_address_tree && ip.len() == 32 {
                    preserved_subtrees.push((*general_name).clone());
                }
            },
            GeneralName::DirectoryName(..) => {
                if !has_self_directory_name {
                    preserved_subtrees.push((*general_name).clone());
                }
            }
            // Other general_name variants should not appear in this subtree
            _ => {},
        }
    }

    // 3. Perform intersection operation among 2 sets indirectly
    //
    // First, if the certificate does not specify any URI restrictions,
    // leave the stored URI be.
    //
    // Assume all elements smong self_xxxx_tree and other_xxxx_tree are homogeneous.
    //
    // For each element in self_xxxx_tree, find intersection with other_xxxx_tree
    // Take union operation at the result of each operations at the end
    // i.e. (S1 U S2 U ... U Sk) n O = (S1 n O) U (S2 n O) U ... U (Sk n O)
    //      as stated in distributive law
    //
    // The with the same argument, but reversing the self_tree and other_tree,
    // For each element in other_xxx_tree, find intersection with that elemenet from self
    // Take union operation of the result of each operations at the end
    // i.e. Sx n (O1 U O2 U ... Oj) = (Sx n O1) U (Sx n O2) U ... U (Sx n Oj)
    //      as stated in distributive law
    //
    // To further simplify, recognize that the brackets of (Sx n O) in the first statement
    // encapsulates a series of union operators, while the bracks perform union operations
    // among themselves as well.
    // Therefore, the order of operations does not matter, stated in the associative law.
    // i.e. S n O = U_(x, y) {Sx n Oy}
    //
    // Now consider all the variants, the processed subtree shall be a union of all variants
    // where the variants are computed as a union of homogeneous intersections.
    // By Identity law, if all heterogeneous intersections returns NULL,
    // union of homogeneous intersections are equivalent to that of heterogeneous intersections.
    //
    // However, an empty set is not what always the correct solution. Here are exceptions:
    //
    // 1. If other_tree does not contain a variant that exists in self_tree,
    //    that variant in self_tree shall be left untouched.
    //
    // 2. Reverse of (1), self_tree does not have definitions on some variant,
    //    while other_tree has.
    // Consider this method is for permitted_subtree operation, no definition means no restriction
    // other_tree would like to impose tighter restriction, so every items of such variant
    // from `other_tree` should be preserved.
    //
    // Both can be fixed by saving all `guaranteed` permitted subtrees before this process
    for self_name in state_subtree.iter() {
        for other_name in cert_subtree.iter() {

            // Make use of subset method, note that all general names are hierarchical
            if self_name.is_subset_of(other_name) {
                preserved_subtrees.push((*self_name).clone())
            } else if other_name.is_subset_of(self_name) {
                preserved_subtrees.push((*other_name).clone())
            }

            // If neither are subset of the other, the intersection shall be none
            // Should both names be homogeneous, it should imply an all-blocking name
            else {
                match (self_name, other_name) {
                    (GeneralName::URI(..), GeneralName::URI(..)) => {
                        preserved_subtrees.push(
                            GeneralName::URI(&[])
                        )
                    },
                    (GeneralName::RFC822Name(..), GeneralName::RFC822Name(..)) => {
                        preserved_subtrees.push(
                            GeneralName::RFC822Name(&[])
                        )
                    },
                    (GeneralName::DNSName(..), GeneralName::DNSName(..)) => {
                        preserved_subtrees.push(
                            GeneralName::DNSName(&[])
                        )
                    },
                    (GeneralName::IPAddress(..), GeneralName::IPAddress(..)) => {
                        preserved_subtrees.push(
                            GeneralName::IPAddress(&[])
                        )
                    },
                    (GeneralName::DirectoryName(..), GeneralName::DirectoryName(..)) => {
                        preserved_subtrees.push(
                            GeneralName::DirectoryName(Name {
                                relative_distinguished_name: Vec::new()
                            })
                        )
                    }

                    // Heterogeneous general name variants
                    _ => {}
                }
            }
        }
    }

    // 4. Perform union operation
    // Again recall that general names are hierarchical
    // If two general names are not disjoint, one must be other's subset
    // Therefore, pruning subsets is sufficient to determine the union.
    // Put the result into state_subtree, as this shall be the output
    //
    // Note: Technically union operation can be a simple no-op
    // But this is performed for the sake of memory space

    state_subtree.clear();
    prune_subset(state_subtree, &mut preserved_subtrees);
}


fn prune_subset<'a>(subtree_out: &mut Vec<GeneralName<'a>>, subtree_in: &mut Vec<GeneralName<'a>>) {
    'outer: for i in 0..subtree_in.len() {
        for j in 0..subtree_in.len() {
            // A few cases to consider:
            // If subtree_i is a strict_subset of subtree_j,
            // then obviously i needs to be ejected
            // However, if Si and Sj are equivalent, then only 1 needs to be ejected
            // the following implementation will eject the one with lower index
            if i != j {
                if subtree_in[i] == subtree_in[j] {
                    if i < j {
                        continue 'outer;
                    }
                } else if subtree_in[i].is_subset_of(&subtree_in[j]) {
                    continue 'outer;
                }
            }
        }
        subtree_out.push(subtree_in[i].clone())
    }
}

// Union operation among 2 subtrees sets, output through state_subtree
pub fn get_subtree_union<'a>(
    state_subtree: &mut Vec<GeneralName<'a>>,
    other_subtree: &Vec<GeneralName<'a>>
) {
    // Join the 2 lists together, and then prune all subsets
    let mut merged_subtrees: Vec<GeneralName> = Vec::new();
    merged_subtrees.extend_from_slice(state_subtree);
    merged_subtrees.extend_from_slice(other_subtree);
    state_subtree.clear();

    prune_subset(state_subtree, &mut merged_subtrees);
}

#[cfg(test)]
mod test {

    use alloc::vec::Vec;
    use super::*;
    use crate::parse::parse_asn1_der_name;

    // Helper to init logger if necessary
    fn init() {
        simple_logger::SimpleLogger::new().init();
    }

    const DNS_EXAMPLE_COM: GeneralName = GeneralName::DNSName(
        b"example.com"
    );
    const DNS_FOO_EXAMPLE: GeneralName = GeneralName::DNSName(
        b"foo.example.com"
    );
    const DNS_EXAMPLE_NET: GeneralName = GeneralName::DNSName(
        b"example.net"
    );
    const DNS_EMPTY: GeneralName = GeneralName::DNSName(
        b""
    );

    /*
     *  Behaviour of IP intersection/union operation
     */
    // 192.168.0.1/24
    const CIDR_IPv4_1: GeneralName = GeneralName::IPAddress(
        &[192, 168, 0, 1, 255, 255, 255, 0]
    );
    // 192.168.0.1/25
    const CIDR_IPv4_2: GeneralName = GeneralName::IPAddress(
        &[192, 168, 0, 1, 255, 255, 255, 128]
    );
    // 192.168.0.1/31
    const CIDR_IPv4_3: GeneralName = GeneralName::IPAddress(
        &[192, 168, 0, 1, 255, 255, 255, 254]
    );
    // 192.72.0.1/24
    const CIDR_IPv4_4: GeneralName = GeneralName::IPAddress(
        &[192, 72, 0, 1, 255, 255, 255, 0]
    );
    // Wildcard
    const CIDR_IPv4_NONE: GeneralName = GeneralName::IPAddress(
        &[]
    );
    // 192.72.0.0/24
    const CIDR_IPv4_5: GeneralName = GeneralName::IPAddress(
        &[192, 72, 0, 0, 255, 255, 255, 0]
    );
    // 192.200.103.0/24
    const CIDR_IPv4_6: GeneralName = GeneralName::IPAddress(
        &[192, 200, 103, 0, 255, 255, 255, 0]
    );
    // 192.200.100.0/22
    const CIDR_IPv4_7: GeneralName = GeneralName::IPAddress(
        &[192, 200, 100, 0, 255, 255, 252, 0]
    );
    // 200.200.100.0/24
    const CIDR_IPv4_8: GeneralName = GeneralName::IPAddress(
        &[200, 200, 100, 0, 255, 255, 255, 0]
    );

    // 2001:0db8:ac10:fe01::/64
    const CIDR_IPv6_1: GeneralName = GeneralName::IPAddress(
        &[0x20, 0x01, 0x0D, 0xB8, 0xAC, 0x10, 0xFE, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    // 2001:0db8:ac10:fe01:1224::/80
    const CIDR_IPv6_2: GeneralName = GeneralName::IPAddress(
        &[0x20, 0x01, 0x0D, 0xB8, 0xAC, 0x10, 0xFE, 0x01,
        0x12, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    // 2001:0db8:ac10:ac01::/64
    const CIDR_IPv6_3: GeneralName = GeneralName::IPAddress(
        &[0x20, 0x01, 0x0D, 0xB8, 0xAC, 0x10, 0xAC, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    // URI
    const URI_HOST_SPECIFIC: GeneralName = GeneralName::URI(
        b"host.example.com"
    );
    const URI_HOST_ONLY: GeneralName = GeneralName::URI(
        b".example.com"
    );
    const URI_DOMAIN_WIDE: GeneralName = GeneralName::URI(
        b"example.com"
    );
    // X400, not supported
    const X400_ROOT: GeneralName = GeneralName::X400Address(
        b"root@example.com"
    );
    const X400_HOST: GeneralName = GeneralName::X400Address(
        b"example.com"
    );
    const X400_DOMAIN_WIDE: GeneralName = GeneralName::X400Address(
        b".example.com"
    );

    macro_rules! test_set_intersection {
        ($($($left_item: expr)*, $($right_item: expr)*, $($expected_item: expr)*);*) => {
            #[test]
            fn test_set_intersection_method() {
                $(
                    let mut state_subtrees: Vec<GeneralName> = Vec::new();
                    $(
                        state_subtrees.push($left_item);
                    )*
                    let mut cert_subtrees: Vec<GeneralName> = Vec::new();
                    $(
                        cert_subtrees.push($right_item);
                    )*
                    let mut expected_subtrees: Vec<GeneralName> = Vec::new();
                    $(
                        expected_subtrees.push($expected_item);
                    )*
                    get_subtree_intersection(&mut state_subtrees, &cert_subtrees);
                    // A very lazy way to check content equality
                    // Wrong permutation will be rejected
                    // although permutation of subtrees should not affect the correctness
                    assert_eq!(
                        state_subtrees,
                        expected_subtrees
                    );
                )*
            }
        };
    }

    macro_rules! test_set_union {
        ($($($left_item: expr)*, $($right_item: expr)*, $($expected_item: expr)*);*) => {
            #[test]
            fn test_set_union_method() {
                $(
                    let mut state_subtrees: Vec<GeneralName> = Vec::new();
                    $(
                        state_subtrees.push($left_item);
                    )*
                    let mut cert_subtrees: Vec<GeneralName> = Vec::new();
                    $(
                        cert_subtrees.push($right_item);
                    )*
                    let mut expected_subtrees: Vec<GeneralName> = Vec::new();
                    $(
                        expected_subtrees.push($expected_item);
                    )*
                    get_subtree_union(&mut state_subtrees, &cert_subtrees);
                    // A very lazy way to check content equality
                    // Wrong permutation will be rejected
                    // although permutation of subtrees should not affect the correctness
                    assert_eq!(
                        state_subtrees,
                        expected_subtrees
                    );
                )*
            }
        };
    }

    test_set_intersection!(
        // Example from RFC 5280 section 6
        DNS_FOO_EXAMPLE, DNS_EXAMPLE_COM, DNS_FOO_EXAMPLE;
        DNS_EXAMPLE_COM, DNS_EXAMPLE_NET, DNS_EMPTY;
        DNS_EXAMPLE_COM, DNS_FOO_EXAMPLE DNS_EXAMPLE_NET, DNS_FOO_EXAMPLE;
        // Intersection between DNS set and empty set
        DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, DNS_EMPTY, DNS_EMPTY;
        DNS_EMPTY, DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, DNS_EMPTY;
        DNS_EXAMPLE_COM DNS_FOO_EXAMPLE DNS_EXAMPLE_NET, DNS_EMPTY, DNS_EMPTY;
        DNS_EMPTY, DNS_EXAMPLE_COM DNS_FOO_EXAMPLE DNS_EXAMPLE_NET, DNS_EMPTY;
        // Intersection between DNS set and unspecified set
        DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, , DNS_EXAMPLE_COM;
        , DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, DNS_EXAMPLE_COM;

        // Intersection between subnet and supernet
        CIDR_IPv4_1, CIDR_IPv4_2 CIDR_IPv4_3, CIDR_IPv4_2;
        CIDR_IPv4_1 CIDR_IPv4_2, CIDR_IPv4_3, CIDR_IPv4_3;
        CIDR_IPv4_2 CIDR_IPv4_3, CIDR_IPv4_1, CIDR_IPv4_2;
        CIDR_IPv4_3, CIDR_IPv4_1 CIDR_IPv4_2, CIDR_IPv4_3;
        // Intersection between disjoint set
        CIDR_IPv4_1, CIDR_IPv4_4, CIDR_IPv4_NONE;
        CIDR_IPv4_4, CIDR_IPv4_1, CIDR_IPv4_NONE;
        // Intersection between empty subtrees and other subtrees (Domination law)
        CIDR_IPv4_NONE, CIDR_IPv4_7, CIDR_IPv4_NONE;
        CIDR_IPv4_NONE, CIDR_IPv4_2, CIDR_IPv4_NONE;
        CIDR_IPv4_NONE, CIDR_IPv4_NONE, CIDR_IPv4_NONE;
        // Multiple IPv4 intersection
        CIDR_IPv4_5 CIDR_IPv4_6, CIDR_IPv4_7 CIDR_IPv4_8, CIDR_IPv4_6;
        // Heterogeneous cross intersection
        CIDR_IPv6_1 CIDR_IPv4_7, CIDR_IPv6_2 CIDR_IPv4_6, CIDR_IPv6_2 CIDR_IPv4_6;
        // Adding a disjoint IPv6 on state subtrees should not alter intersection result
        CIDR_IPv6_1 CIDR_IPv4_7 CIDR_IPv6_3, CIDR_IPv6_2 CIDR_IPv4_6, CIDR_IPv6_2 CIDR_IPv4_6;
        // Heterogeneous disjoint intersection, effectively self union
        CIDR_IPv6_1 CIDR_IPv6_2, CIDR_IPv4_7 CIDR_IPv4_6, CIDR_IPv6_1 CIDR_IPv4_7;

        // Intersection between heterogeneous variants
        DNS_FOO_EXAMPLE, CIDR_IPv6_1, DNS_FOO_EXAMPLE CIDR_IPv6_1;
        DNS_FOO_EXAMPLE CIDR_IPv6_2, CIDR_IPv6_1 DNS_EXAMPLE_NET, DNS_EMPTY CIDR_IPv6_2;

        // Intersection with variants that do not support such operation
        X400_ROOT DNS_FOO_EXAMPLE CIDR_IPv6_2, CIDR_IPv6_1 DNS_EXAMPLE_NET, DNS_EMPTY CIDR_IPv6_2
    );

    test_set_union!(
        // Example from RFC 5280 section 6
        DNS_FOO_EXAMPLE, DNS_EXAMPLE_COM, DNS_EXAMPLE_COM;
        DNS_EXAMPLE_COM, DNS_EXAMPLE_NET, DNS_EXAMPLE_COM DNS_EXAMPLE_NET;
        DNS_EXAMPLE_COM, DNS_FOO_EXAMPLE DNS_EXAMPLE_NET, DNS_EXAMPLE_COM DNS_EXAMPLE_NET;
        // Union between DNS set and empty set
        DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, DNS_EMPTY, DNS_EXAMPLE_COM;
        DNS_EMPTY, DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, DNS_EXAMPLE_COM;
        DNS_EXAMPLE_COM DNS_FOO_EXAMPLE DNS_EXAMPLE_NET, DNS_EMPTY, DNS_EXAMPLE_COM DNS_EXAMPLE_NET;
        DNS_EMPTY, DNS_EXAMPLE_COM DNS_FOO_EXAMPLE DNS_EXAMPLE_NET, DNS_EXAMPLE_COM DNS_EXAMPLE_NET;
        // Union between DNS set and unspecified set
        DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, , DNS_EXAMPLE_COM;
        , DNS_EXAMPLE_COM DNS_FOO_EXAMPLE, DNS_EXAMPLE_COM;

        // Union between subnet and supernet
        CIDR_IPv4_1, CIDR_IPv4_2 CIDR_IPv4_3, CIDR_IPv4_1;
        CIDR_IPv4_1 CIDR_IPv4_3, CIDR_IPv4_2, CIDR_IPv4_1;
        CIDR_IPv4_2 CIDR_IPv4_3, CIDR_IPv4_1, CIDR_IPv4_1;
        CIDR_IPv4_2, CIDR_IPv4_1 CIDR_IPv4_3, CIDR_IPv4_1;
        // Union between empty subtrees and other subtrees (Identity law)
        CIDR_IPv4_NONE, CIDR_IPv4_1, CIDR_IPv4_1;
        CIDR_IPv4_NONE, CIDR_IPv4_6, CIDR_IPv4_6;
        CIDR_IPv4_NONE, CIDR_IPv4_NONE, CIDR_IPv4_NONE;
        // Multiple IPv4 intersection
        CIDR_IPv4_5 CIDR_IPv4_6, CIDR_IPv4_7 CIDR_IPv4_8, CIDR_IPv4_5 CIDR_IPv4_7 CIDR_IPv4_8;
        // Heterogeneous cross union
        CIDR_IPv6_1 CIDR_IPv4_7, CIDR_IPv6_2 CIDR_IPv4_6, CIDR_IPv6_1 CIDR_IPv4_7;
        // Adding a disjoint IPv6 on state subtrees should mean appending the disjoin subtree
        CIDR_IPv6_1 CIDR_IPv6_3 CIDR_IPv4_7, CIDR_IPv6_2 CIDR_IPv4_6, CIDR_IPv6_1 CIDR_IPv6_3 CIDR_IPv4_7;
        // Heterogeneous disjoint union, effectively self union
        CIDR_IPv6_1 CIDR_IPv6_2, CIDR_IPv4_7 CIDR_IPv4_6, CIDR_IPv6_1 CIDR_IPv4_7;

        // Union between heterogeneous variants
        DNS_FOO_EXAMPLE, CIDR_IPv6_1, DNS_FOO_EXAMPLE CIDR_IPv6_1;
        DNS_FOO_EXAMPLE CIDR_IPv6_2, CIDR_IPv6_1 DNS_EXAMPLE_NET, DNS_FOO_EXAMPLE CIDR_IPv6_1 DNS_EXAMPLE_NET;

        // Intersection with variants that do not support such operation
        X400_ROOT DNS_FOO_EXAMPLE CIDR_IPv6_2, CIDR_IPv6_1 DNS_EXAMPLE_NET, X400_ROOT DNS_FOO_EXAMPLE CIDR_IPv6_1 DNS_EXAMPLE_NET
    );

    #[test]
    fn test_directory_name_operations() {
        // Less specific directory name
        let broad_name = parse_asn1_der_name(
            &[0x30, 0x22, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
            0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a,
            0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41]
        ).unwrap().1;

        // More specific directory name
        let specific_name = parse_asn1_der_name(
            &[0x30, 0x2e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
            0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a,
            0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41,
            0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x01, 0x70]
        ).unwrap().1;

        // Disjoint name
        let disjoint_name = parse_asn1_der_name(
            &[0x30, 0x22, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
            0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a,
            0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x42]
        ).unwrap().1;

        // Permutated name
        let permutated_name = parse_asn1_der_name(
            &[0x30, 0x22, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a,
            0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41,
            0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
            0x02, 0x55, 0x53]
        ).unwrap().1;

        // Empty name
        let empty_name = Name {
            relative_distinguished_name: Vec::new()
        };

        assert!(specific_name.belongs_to(&broad_name));
        assert!(!disjoint_name.belongs_to(&broad_name));
        assert!(!disjoint_name.belongs_to(&specific_name));
        assert!(specific_name != broad_name);
        assert!(broad_name != specific_name);
        assert!(broad_name == permutated_name);

        let mut state_subtrees: Vec<GeneralName> = Vec::new();
        let mut cert_subtrees: Vec<GeneralName> = Vec::new();
        let mut expected_subtrees: Vec<GeneralName> = Vec::new();

        let broad_general_name = GeneralName::DirectoryName(broad_name);
        let specific_general_name = GeneralName::DirectoryName(specific_name);
        let disjoint_general_name = GeneralName::DirectoryName(disjoint_name);
        let permutated_general_name = GeneralName::DirectoryName(permutated_name);
        let empty_general_name = GeneralName::DirectoryName(empty_name);

        assert!(specific_general_name.is_subset_of(&broad_general_name));
        assert!(!broad_general_name.is_subset_of(&specific_general_name));
        assert!(specific_general_name != broad_general_name);

        assert!(empty_general_name.is_subset_of(&specific_general_name));
        assert!(!specific_general_name.is_subset_of(&empty_general_name));

        state_subtrees.push(broad_general_name.clone());
        cert_subtrees.push(specific_general_name.clone());
        expected_subtrees.push(specific_general_name.clone());
        get_subtree_intersection(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(broad_general_name.clone());
        cert_subtrees.push(specific_general_name.clone());
        expected_subtrees.push(broad_general_name.clone());
        get_subtree_union(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        // Behaviour with empty name
        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(empty_general_name.clone());
        cert_subtrees.push(specific_general_name.clone());
        expected_subtrees.push(empty_general_name.clone());
        get_subtree_intersection(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(empty_general_name.clone());
        cert_subtrees.push(specific_general_name.clone());
        expected_subtrees.push(specific_general_name.clone());
        get_subtree_union(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(specific_general_name.clone());
        cert_subtrees.push(empty_general_name.clone());
        expected_subtrees.push(empty_general_name.clone());
        get_subtree_intersection(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(specific_general_name.clone());
        cert_subtrees.push(empty_general_name.clone());
        expected_subtrees.push(specific_general_name.clone());
        get_subtree_union(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        // Intersection / Union with permutated name
        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(broad_general_name.clone());
        state_subtrees.push(specific_general_name.clone());
        cert_subtrees.push(permutated_general_name.clone());
        expected_subtrees.push(broad_general_name.clone());
        get_subtree_intersection(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(broad_general_name.clone());
        cert_subtrees.push(permutated_general_name.clone());
        cert_subtrees.push(disjoint_general_name.clone());
        expected_subtrees.push(permutated_general_name.clone());
        expected_subtrees.push(disjoint_general_name.clone());
        get_subtree_union(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);

        // DirectoryName operation with empty list
        state_subtrees.clear();
        cert_subtrees.clear();
        expected_subtrees.clear();
        state_subtrees.push(broad_general_name.clone());
        state_subtrees.push(specific_general_name.clone());
        expected_subtrees.push(broad_general_name.clone());
        get_subtree_intersection(&mut state_subtrees, &cert_subtrees);
        assert_eq!(state_subtrees, expected_subtrees);
    }
}
