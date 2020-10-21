#![no_std]

#[macro_use]
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
pub enum Error {
    PropagatedError(smoltcp::Error),
    ParsingError(nom::error::ErrorKind),
    EncryptionError,
    DecryptionError,
    CapacityError,
}
