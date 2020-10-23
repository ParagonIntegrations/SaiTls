use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub tbs_certificate: TBSCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: &'a [u8]
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
