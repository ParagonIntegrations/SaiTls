#![no_std]

extern crate alloc;

pub mod tls;
pub mod tls_packet;
pub mod parse;
pub mod buffer;
pub mod key;
pub mod session;
pub mod certificate;

use nom::error::ParseError;

// TODO: Implement errors
// Details: Encapsulate smoltcp & nom errors
#[derive(Debug, Clone)]
pub enum Error {
    PropagatedError(smoltcp::Error),
    ParsingError,
    EncryptionError,
    DecryptionError,
    CapacityError,
    SignatureValidationError,
}
