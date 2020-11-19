// A blank implementor of RngCore that is NOT random
// Justification: RSA padding scheme for verifying PSS signature
// 1. Why is there a static lifetime bound?
// 2. Why need random? It is just signature verification.
// Anyway, the RSAPublicKey::verify() method does NOT care about random at all :)

use rand_core::{RngCore, Error};
use byteorder::{ByteOrder, NetworkEndian, BigEndian};

pub struct FakeRandom {}

impl RngCore for FakeRandom {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
}

// A construct to allow a random slice to be generated in advance and buffered
// The generated value will then be returned deterministically
// Motivation:
// This is to prevent the use of static mutable reference, thus unsafe function calls
// A TLS socket is not meant to be a singleton

use generic_array::GenericArray;
use generic_array::ArrayLength;

pub struct OneTimeRandom<Size: ArrayLength<u8>> {
    stored_slice: GenericArray<u8, Size>
}

impl<Size: ArrayLength<u8>> OneTimeRandom<Size> {
    pub fn new(slice: &[u8]) -> Self {
        let mut stored_slice: GenericArray<u8, Size> = Default::default();
        &stored_slice[..(slice.len())].clone_from_slice(slice);
        Self {
            stored_slice
        }
    }
}

impl<Size: ArrayLength<u8>> RngCore for OneTimeRandom<Size> {
    fn next_u32(&mut self) -> u32 {
        NetworkEndian::read_u32(&self.stored_slice)
    }

    fn next_u64(&mut self) -> u64 {
        NetworkEndian::read_u64(&self.stored_slice)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.clone_from_slice(&self.stored_slice[..(dest.len())]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}
