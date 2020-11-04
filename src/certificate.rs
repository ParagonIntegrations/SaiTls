use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

use generic_array::GenericArray;

use crate::parse::parse_asn1_der_rsa_public_key;
use crate::parse::parse_rsa_ssa_pss_parameters;

use crate::Error as TlsError;
use crate::session::CertificatePublicKey;
use crate::oid::*;
use crate::fake_rng::FakeRandom;

use sha1::{Sha1, Digest};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use rsa::{PublicKey, RSAPublicKey, PaddingScheme, BigUint, Hash};

use alloc::vec::Vec;
use heapless::{ Vec as HeaplessVec, consts::* };

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
// TODO: Remove this method, it will be replaced
pub fn validate_root_certificate(cert: &Certificate) -> Result<bool, TlsError> {
    // Verify Signature
    match cert.signature_algorithm.algorithm {
        SHA1_WITH_RSA_ENCRYPTION => {
            let mut hasher = Sha1::new();
            hasher.update(cert.tbs_certificate_encoded);

            log::info!("Created hashed");

            let (_, (modulus, exponent)) = parse_asn1_der_rsa_public_key(
                cert.tbs_certificate.subject_public_key_info.subject_public_key
            ).map_err(|_| TlsError::ParsingError)?;

            log::info!("Modulus: {:?}", modulus);
            log::info!("Exponent: {:?}", exponent);

            let rsa_public_key = RSAPublicKey::new(
                BigUint::from_bytes_be(modulus),
                BigUint::from_bytes_be(exponent)
            ).map_err(|_| TlsError::SignatureValidationError)?;

            let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1));
            let verify_result = rsa_public_key.verify(
                padding,
                &hasher.finalize(),
                cert.signature_value
            ).unwrap();
            Ok(true)
        },
        _ => Err(TlsError::SignatureValidationError)
    }
}

impl<'a> Certificate<'a> {
    // Return the public key, if used for RSA
    pub fn return_rsa_public_key(&self) -> Result<RSAPublicKey, ()> {
        if self.signature_algorithm.algorithm != SHA1_WITH_RSA_ENCRYPTION {
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
            RSA_ENCRYPTION => {
                log::info!("Chose rsa encryption");
                log::info!("Entire key: {:X?}", self.tbs_certificate.subject_public_key_info.subject_public_key);
                let (_, (modulus, exponent)) = parse_asn1_der_rsa_public_key(
                    self.tbs_certificate.subject_public_key_info.subject_public_key
                ).map_err(|_| ())?;
                log::info!("Modulus: {:X?}\n, Exponent: {:X?}", modulus, exponent);

                log::info!("Big int modulus: {:?}", BigUint::from_bytes_be(modulus));
        
                let public_key = RSAPublicKey::new(
                    BigUint::from_bytes_be(modulus),
                    BigUint::from_bytes_be(exponent)
                ).map_err(|_| ())?;
                log::info!("Got rsa key parts");
                Ok(
                    CertificatePublicKey::RSA {
                        cert_rsa_public_key: public_key
                    }
                )
            },
            ID_EC_PUBLIC_KEY => {
                // Check the type of EC, only support secp256r1
                // Will definitely NOT support custom curve
                if algorithm_identifier.parameters != PRIME256V1 {
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

    // Validate certificate's signature
    // Do not be confused with TLS Certificate Verify
    pub fn validate_signature(&self) -> Result<(), TlsError> {
        let sig_alg = self.signature_algorithm.algorithm;

        // Prepare hash value
        match sig_alg {
            SHA1_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1));
                let hashed = Sha1::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                self.get_cert_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA224_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_224));
                let hashed = Sha224::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                self.get_cert_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA256_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
                let hashed = Sha256::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                self.get_cert_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA384_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_384));
                let hashed = Sha384::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                self.get_cert_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },

            SHA512_WITH_RSA_ENCRYPTION => {
                let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_512));
                let hashed = Sha512::digest(self.tbs_certificate_encoded);
                let sig = self.signature_value;
                self.get_cert_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .get_rsa_public_key()
                    .map_err(|_| TlsError::SignatureValidationError)?
                    .verify(padding, &hashed, sig)
                    .map_err(|_| TlsError::SignatureValidationError)
            },
            // Further process the signature algorithm before creating digests
            // i.e. PSS, OAEP
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
                        self.get_cert_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .get_rsa_public_key()
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
                        self.get_cert_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .get_rsa_public_key()
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
                        self.get_cert_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .get_rsa_public_key()
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
                        self.get_cert_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .get_rsa_public_key()
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
                        self.get_cert_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .get_rsa_public_key()
                            .map_err(|_| TlsError::SignatureValidationError)?
                            .verify(padding, &hashed, sig)
                            .map_err(|_| TlsError::SignatureValidationError)
                    },
                    _ => todo!()
                }
            }
            _ => todo!()
        }

    }
}
