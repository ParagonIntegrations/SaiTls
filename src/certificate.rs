use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

pub struct Certificate<'a> {
    tbs_certificate: TBSCertificate<'a>,
    signature_algorithm: AlgorithmIdentifier<'a>,
    signature_value: &'a [u8]
}

pub struct TBSCertificate<'a> {
    version: Version,
    serial_number: &'a [u8],
    signature: AlgorithmIdentifier<'a>,
    issuer: &'a [u8],
    validity: Validity<'a>,
    subject: &'a [u8],
    subject_public_key_info: SubjectPublicKeyInfo<'a>,
    issuer_unique_id: Option<&'a [u8]>,
    subject_unique_id: Option<&'a [u8]>,
    extensions: Extensions,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum Version {
    #[num_enum(default)]
    v1 = 0,
    v2 = 1,
    v3 = 2,
}

pub struct Validity<'a> {
    not_before: Time<'a>,
    not_after: Time<'a>,
}

pub enum Time<'a> {
    UTCTime(&'a [u8]),
    GeneralizedTime(&'a [u8]),
}

pub struct SubjectPublicKeyInfo<'a> {
    algorithm: AlgorithmIdentifier<'a>,
    subject_public_key: &'a [u8],
}

pub struct Extensions {
    
}

pub struct AlgorithmIdentifier<'a> {
    pub algorithm: &'a [u8],
    pub parameters: &'a [u8],
}
