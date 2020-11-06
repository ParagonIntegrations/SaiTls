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
// This padding scheme is not supported by RSA for verification 
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

// Hash OIDs
pub const ID_SHA1: &'static [u8] =
    &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
pub const ID_SHA224: &'static [u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
pub const ID_SHA256: &'static [u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
pub const ID_SHA384: &'static [u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
pub const ID_SHA512: &'static [u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

// Mask Generation Function (mgf1)
pub const ID_MGF1: &'static [u8] =
    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08];

// Algorithm Identifier with specific parameters
pub const ID_P_SPECIFIED: &'static [u8] =
    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x09];

// Extensions
pub const CERT_KEY_USAGE:               &'static [u8] = &[85, 29, 15];                      // 2.5.29.15
pub const CERT_POLICIES:                &'static [u8] = &[85, 29, 32];                      // 2.5.29.32
pub const CERT_BASIC_CONSTRAINTS:       &'static [u8] = &[85, 29, 19];                      // 2.5.29.19
pub const CERT_EXT_KEY_USAGE:           &'static [u8] = &[85, 29, 37];                      // 2.5.29.37
pub const CERT_INHIBIT_ANY_POLICY:      &'static [u8] = &[85, 29, 54];                      // 2.5.29.54
pub const CERT_SUBJECTALTNAME:          &'static [u8] = &[85, 29, 17];                      // 2.5.29.17
// Extended Key Extensions
pub const ANY_EXTENDED_KEY_USAGE:       &'static [u8] = &[85, 29, 37, 0];                   // 2.5.29.37.0
pub const ID_KP_SERVER_AUTH:            &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 1];         // 1.3.6.1.5.5.7.3.1
pub const ID_KP_CLIENT_AUTH:            &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 2];         // 1.3.6.1.5.5.7.3.2
pub const ID_KP_CODE_SIGNING:           &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 3];         // 1.3.6.1.5.5.7.3.3
pub const ID_KP_EMAIL_PROTECTION:       &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 4];         // 1.3.6.1.5.5.7.3.4
pub const ID_KP_TIME_STAMPING:          &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 8];         // 1.3.6.1.5.5.7.3.8
pub const ID_KP_OCSP_SIGNING:           &'static [u8] = &[43, 6, 1, 5, 5, 7, 3, 9];