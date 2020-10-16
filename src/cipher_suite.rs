use p256::{EncodedPoint, AffinePoint, ecdh::EphemeralSecret, ecdh::SharedSecret};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use ccm::{Ccm, consts::*};
use aes_gcm::aes::Aes128;
use aes_gcm::{AeadInPlace, NewAead};
use generic_array::GenericArray;
use rand_core::{ RngCore, CryptoRng };
use sha2::{ Digest, Sha256, Sha384, Sha512 };
use heapless::Vec;
use hkdf::Hkdf;

use crate::Error as TlsError;
use crate::tls_packet::CipherSuite as CipherSuiteField;
use crate::key::*;

// A structure representing the block cipher and the hashes
pub(crate) enum CipherSuite {
	// Handshake is still proceeding, no cipher can be produced yet,
	// Though hashes still has to be prepared for deriving key later,
	// This enum offers all possible hashes that could be needed
	// i.e. SHA256 and SHA384
	Undetermined {
		sha_256: Sha256,
		sha_384: Sha384,
	},

	// Established cipher suites
	// Contains a block cipher (GCM/CCM/ChaChaPoly)
	// Contains a hash function (SHA256/SHA384)
	TLS_AES_128_GCM_SHA256 {
		aes_128_gcm: Aes128Gcm,
		sha_256: Sha256,
	},
	TLS_AES_256_GCM_SHA384 {
		aes_256_gcm: Aes256Gcm,
		sha_384: Sha384,
	},
	TLS_CHACHA20_POLY1305_SHA256 {
		chacha20_poly1305: ChaCha20Poly1305,
		sha_256: Sha256,
	},
	TLS_AES_128_CCM_SHA256 {
		ccm: Ccm<Aes128, U16, U12>,
		sha_256: Sha256,
	},
}


impl CipherSuite {
	pub(crate) fn new() -> Self {
		CipherSuite::Undetermined {
			sha_256: Sha256::new(),
			sha_384: Sha384::new(),
		}
	}

	// Assume no PSK, establish ciphersuite along side handshake secret
	// Need to update hash function before calling
	pub(crate) fn establish(
		self,
		field: CipherSuiteField,
		ecdhe_shared: SharedSecret
	) -> Self {
		use CipherSuiteField::*;

		let (sha_256, sha_384) = {
			if let CipherSuite::Undetermined {
				sha_256,
				sha_384,
			} = self {
				(sha_256, sha_384)
			} else {
				// TODO: Implement key change
				return self;
			}
		};

		match field {
			TLS_AES_128_GCM_SHA256 | TLS_CHACHA20_POLY1305_SHA256 |
			TLS_AES_128_CCM_SHA256 => {
				// Compute early_secret in HKDF, without PSK
				let empty_hash = Sha256::new().chain("");
				let early_secret = Hkdf::<Sha256>::new(None, &[0; 32]);

				// Calculate derived secret
				let derived_secret = derive_secret(
					&early_secret,
					"derived",
					empty_hash
				);

				// Calculate handshake secret in HKDF
				let handshake_secret = Hkdf::<Sha256>::new(
					Some(&derived_secret),
					ecdhe_shared.as_bytes()
				);

				// Calculate client_handshake_traffic_secret
				let client_handshake_traffic_secret = derive_secret(
					&handshake_secret,
					"c hs traffic",
					sha_256.clone()
				);

				// Calculate server_handshake_traffic_secret
				let server_handshake_traffic_secret = derive_secret(
					&handshake_secret,
					"c hs traffic",
					sha_256.clone()
				);

				// let client_write_key = hkdf_expand_label(
				//
				// );
			}
			_ => todo!()
		}

		todo!()

		// // Compute HKDF
		// let (hash, empty_hash, hkdf) = match field {
		// 	TLS_AES_128_GCM_SHA256 |
		// 	TLS_CHACHA20_POLY1305_SHA256 |
		// 	TLS_AES_128_CCM_SHA256 => {
		// 		(
		// 			sha_256,
		// 			Sha256::new().chain(""),
		// 			Hkdf::<Sha256>::new(None, &[0; 32])
		// 		)
		// 	},
		// 	TLS_AES_256_GCM_SHA384 => {
		// 		(
		// 			sha_384,
		// 			Sha384::new().chain(""),
		// 			Hkdf::<Sha384>::new(None, &[0; 48])
		// 		)
		// 	}
		// };

		// // get_derived_secret, then insert ECDHE shared secret
		// let derived_secret = derive_secret(hkdf, "derived", empty_hash);
		
		// let (key, iv) = match field {
		// 	TLS_AES_128_GCM_SHA256 |
		// 	TLS_CHACHA20_POLY1305_SHA256 |
		// 	TLS_AES_128_CCM_SHA256 => {
		// 		let hkdf = Hkdf::<Sha256>::new(
		// 			Some(&derived_secret),
		// 			ecdhe_shared.as_bytes()
		// 		);
		// 		let client_handshake_traffic_secret = derive_secret(
		// 			hkdf,
		// 			"c hs traffic",
		// 			sha256.clone(),
		// 		);
		// 	},
		// 	TLS_AES_256_GCM_SHA384 => {
		// 		Hkdf::<Sha384>::new(
		// 			Some(&derived_secret),
		// 			ecdhe_shared.as_bytes()
		// 		)
		// 	}
		// };
	}
}

// macro_rules! impl_cipher {
// 	($($cipher_name: ident),+) => {
// 		impl Cipher {
// 			pub(crate) fn encrypt<T>(&self, rng: &mut T, associated_data: &[u8], buffer: &mut Vec<u8>) -> core::result::Result<(), TlsError>
// 			where
// 				T: RngCore + CryptoRng
// 			{
// 				// All 4 supported Ciphers use a nonce of 12 bytes
// 				let mut nonce_array: [u8; 12] = [0; 12];
// 				rng.fill_bytes(&mut nonce_array);
// 				use Cipher::*;
// 				match self {
// 					$(
// 						$cipher_name(cipher) => {
// 							cipher.encrypt_in_place(
// 								&GenericArray::from_slice(&nonce_array),
// 								associated_data,
// 								buffer
// 							).map_err(
// 								|_| TlsError::EncryptionError
// 							)
// 						}
// 					)+
// 				}
// 			}

// 			pub(crate) fn decrypt<T>(&self, rng: &mut T, associated_data: &[u8], buffer: &mut Vec<u8>) -> core::result::Result<(), TlsError>
// 			where
// 				T: RngCore + CryptoRng
// 			{
// 				// All 4 supported Ciphers use a nonce of 12 bytes
// 				let mut nonce_array: [u8; 12] = [0; 12];
// 				rng.fill_bytes(&mut nonce_array);
// 				use Cipher::*;
// 				match self {
// 					$(
// 						$cipher_name(cipher) => {
// 							cipher.decrypt_in_place(
// 								&GenericArray::from_slice(&nonce_array),
// 								associated_data,
// 								buffer
// 							).map_err(
// 								|_| TlsError::EncryptionError
// 							)
// 						}
// 					)+
// 				}
// 			}
// 		}
// 	}
// }

// impl_cipher!(
// 	TLS_AES_128_GCM_SHA256,
// 	TLS_AES_256_GCM_SHA384,
// 	TLS_CHACHA20_POLY1305_SHA256,
// 	TLS_AES_128_CCM_SHA256
// );