use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

use generic_array::GenericArray;

use crate::parse::parse_asn1_der_rsa_public_key;
use crate::Error as TlsError;
use crate::session::CertificatePublicKey;

use sha1::{Sha1, Digest};
use rsa::{PublicKey, RSAPublicKey, PaddingScheme, BigUint, Hash};

use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub tbs_certificate: TBSCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: &'a [u8],
    pub tbs_certificate_encoded: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct TBSCertificate<'a> {
    pub version: Version,
    pub serial_number: &'a [u8],
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: &'a [u8],
    pub validity: Validity<'a>,
    pub subject: &'a [u8],
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
pub struct Validity<'a> {
    pub not_before: Time<'a>,
    pub not_after: Time<'a>,
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

    // Permitted subtrees and excluded subtrees are not implemented
    // SubjectAlternativeName,

    BasicConstraints {
        is_ca: bool,
        path_len_constraint: Option<u8>,
    },

    // Permitted subtrees and excluded subtrees are not implemented
    // NameConstraints,

    // Policy mapping will not be supported
    // PolicyConstraints,

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

// TODO: MOve this to impl block of Certificate
// Verify self-signed root certificate parsed certificate
pub fn validate_root_certificate(cert: &Certificate) -> Result<bool, TlsError> {
    // Verify Signature
    match cert.signature_algorithm.algorithm {
        SHA1_WITH_RSA_ENCRYPTION => {
            let mut hasher = Sha1::new();
            hasher.update(cert.tbs_certificate_encoded);

            let (_, (modulus, exponent)) = parse_asn1_der_rsa_public_key(
                cert.tbs_certificate.subject_public_key_info.subject_public_key
            ).map_err(|_| TlsError::ParsingError)?;

            let rsa_public_key = RSAPublicKey::new(
                BigUint::from_bytes_be(modulus),
                BigUint::from_bytes_be(exponent)
            ).map_err(|_| TlsError::SignatureValidationError)?;

            let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1));
            let verify_result = rsa_public_key.verify(
                padding,
                &hasher.finalize(),
                cert.signature_value
            );
            Ok(verify_result.is_ok())
        }
    }
}

impl<'a> Certificate<'a> {
    // Return the public key, if used for RSA
    pub fn return_rsa_public_key(&self) -> Result<RSAPublicKey, ()> {
        if self.signature_algorithm.algorithm != oid::SHA1_WITH_RSA_ENCRYPTION {
            return Err(());
        }
        let (_, (modulus, exponent)) = parse_asn1_der_rsa_public_key(
            self.tbs_certificate.subject_public_key_info.subject_public_key
        ).map_err(|_| ())?;

        RSAPublicKey::new(
            BigUint::from_bytes_be(modulus),
            BigUint::from_bytes_be(exponent)
        ).map_err(|_| ())
    }

    // General return public key method
    // TODO: Replace return_rsa_public_key() with this method
    // Things to change: session.rs: client_update_for_wait_cert_cr
    pub(crate) fn get_cert_public_key(&self) -> Result<CertificatePublicKey, ()> {
        let public_key_info = &self.tbs_certificate.subject_public_key_info;
        let algorithm_identifier = &public_key_info.algorithm;

        // 3 possibilities: RSA_ENCRYPTION, ID_EC_PUBLIC_KEY, and EdDSA25519
        match algorithm_identifier.algorithm {
            oid::RSA_ENCRYPTION => {
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
            oid::ID_EC_PUBLIC_KEY => {
                // Check the type of EC, only support secp256r1
                // Will definitely NOT support custom curve
                if algorithm_identifier.parameters != oid::PRIME256V1 {
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
            oid::ID_EDDSA_25519 => {
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
}

// TODO: Centralize OID, another OID module can be found in `parse.rs`
mod oid {
    // RSA public key
    pub const RSA_ENCRYPTION: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        
    // EC public key for secp256r1
    pub const ID_EC_PUBLIC_KEY: &'static [u8] = 
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    pub const PRIME256V1: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // EDDSA25519 public key, signature algorithm
    pub const ID_EDDSA_25519: &'static [u8] =
        &[0x2B, 0x65, 0x70];
    
    // Supported Signature Algorithm (RFC 4055, RFC 3279)
    // PKCS #1 v1.5
    pub const SHA1_WITH_RSA_ENCRYPTION: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    pub const SHA224_WITH_RSA_ENCRYPTION: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E];
    pub const SHA256_WITH_RSA_ENCRYPTION: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    pub const SHA384_WITH_RSA_ENCRYPTION: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
    pub const SHA512_WITH_RSA_ENCRYPTION: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
    
    // RSASSA_PSS
    pub const ID_RSASSA_PSS: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
    
    // RSAES_OAEP
    pub const ID_RSAES_OAEP: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07];

    // ECDSA signature algorithms, from OID repo
    pub const ECDSA_WITH_SHA1: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
    pub const ECDSA_WITH_SHA224: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01];
    pub const ECDSA_WITH_SHA256: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    pub const ECDSA_WITH_SHA384: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
    pub const ECDSA_WITH_SHA512: &'static [u8] =
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];
}

