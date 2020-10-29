// A blank implementor of RngCore that is NOT random
// Justification: RSA padding scheme for verifying PSS signature
// 1. Why is there a static lifetime bound?
// 2. Why need random? It is just signature verification.
// Anyway, the RSAPublicKey::verify() method does NOT care about random at all :)

use rand_core::{RngCore, Error};

pub (crate) struct FakeRandom {}

impl RngCore for FakeRandom {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
}
