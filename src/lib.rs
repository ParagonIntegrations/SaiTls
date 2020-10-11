#![no_std]

pub mod tls;
pub mod tls_packet;
pub mod parse;

pub enum Error {
    PropagatedError(smoltcp::Error),
    ParsingError()
}