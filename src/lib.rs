#![no_std]

extern crate alloc;

pub mod tls;
pub mod tls_packet;
pub mod parse;
pub mod buffer;
pub mod key;
pub mod session;
pub mod certificate;
pub mod fake_rng;
pub mod oid;
pub mod set;

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
    TimeValidityError,
    CertificateIssuerMismatch,
    CertificateSubjectNotPermitted,
    CertificateSubjectExcluded,
    CertificatePolicyError,
    CertificateVersionError,
}

impl From<smoltcp::Error> for Error {
    fn from(error: smoltcp::Error) -> Self {
        Self::PropagatedError(error)
    }
}

pub trait TlsRng: rand_core::RngCore + rand_core::CryptoRng {}

use smoltcp as net;

use net::socket::SocketSet;
use net::iface::EthernetInterface;
use net::time::Instant;
use net::phy::Device;

use crate::set::TlsSocketSet;

// One-call function for polling all sockets within socket set
pub fn poll<DeviceT>(
    sockets: &mut SocketSet,
    tls_sockets: &mut TlsSocketSet,
    iface: &mut EthernetInterface<DeviceT>,
    now: Instant
) -> Result<bool, Error>
where
    DeviceT: for<'d> Device<'d>
{
    tls_sockets.polled_by(sockets)?;
    iface.poll(sockets, now).map_err(Error::PropagatedError)
}
