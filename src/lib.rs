#![no_std]

#[macro_use]
extern crate alloc;

pub mod tls;
pub mod tls_packet;
pub mod parse;

// TODO: Implement errors
// Details: Encapsulate smoltcp & nom errors
pub enum Error {
    PropagatedError(smoltcp::Error),
    ParsingError,
    EncryptionError,
    CapacityError,
}