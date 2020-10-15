use p256::{EncodedPoint, AffinePoint, ecdh::EphemeralSecret, ecdh::SharedSecret};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use ccm::{Ccm, consts::*};
use aes_gcm::aes::Aes128;
use aes_gcm::{AeadInPlace, NewAead};
use generic_array::GenericArray;
use rand_core::{ RngCore, CryptoRng };
use alloc::vec::Vec;
use crate::Error as TlsError;

pub(crate) enum Cipher {
	TLS_AES_128_GCM_SHA256(Aes128Gcm),
	TLS_AES_256_GCM_SHA384(Aes256Gcm),
	TLS_CHACHA20_POLY1305_SHA256(ChaCha20Poly1305),
	TLS_AES_128_CCM_SHA256(Ccm<Aes128, U16, U12>)
}

macro_rules! impl_cipher {
	($($cipher_name: ident),+) => {
		impl Cipher {
			pub(crate) fn encrypt<T>(&self, rng: &mut T, associated_data: &[u8], buffer: &mut Vec<u8>) -> core::result::Result<(), TlsError>
			where
				T: RngCore + CryptoRng
			{
				// All 4 supported Ciphers use a nonce of 12 bytes
				let mut nonce_array: [u8; 12] = [0; 12];
				rng.fill_bytes(&mut nonce_array);
				use Cipher::*;
				match self {
					$(
						$cipher_name(cipher) => {
							cipher.encrypt_in_place(
								&GenericArray::from_slice(&nonce_array),
								associated_data,
								buffer
							).map_err(
								|_| TlsError::EncryptionError
							)
						}
					)+
				}
			}

			pub(crate) fn decrypt<T>(&self, rng: &mut T, associated_data: &[u8], buffer: &mut Vec<u8>) -> core::result::Result<(), TlsError>
			where
				T: RngCore + CryptoRng
			{
				// All 4 supported Ciphers use a nonce of 12 bytes
				let mut nonce_array: [u8; 12] = [0; 12];
				rng.fill_bytes(&mut nonce_array);
				use Cipher::*;
				match self {
					$(
						$cipher_name(cipher) => {
							cipher.decrypt_in_place(
								&GenericArray::from_slice(&nonce_array),
								associated_data,
								buffer
							).map_err(
								|_| TlsError::EncryptionError
							)
						}
					)+
				}
			}
		}
	}
}

impl_cipher!(
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_128_CCM_SHA256
);