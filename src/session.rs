use p256::{ EncodedPoint, ecdh::EphemeralSecret };
use heapless::{ Vec, consts::* };
use sha2::{ Digest, Sha256, Sha384, digest::FixedOutput };
use aes_gcm::{ Aes128Gcm, Aes256Gcm, aes::Aes128 };
use aes_gcm::{ AeadInPlace, NewAead, aead::Buffer };
use chacha20poly1305::ChaCha20Poly1305;
use ccm::Ccm;
use hkdf::Hkdf;
use generic_array::GenericArray;

use core::convert::AsRef;
use core::cell::RefCell;

use crate::tls::TlsState;
use crate::tls_packet::CipherSuite;
use crate::key::*;
use crate::Error;

type Aes128Ccm = Ccm<Aes128, U16, U12>;

pub(crate) struct Session {
	state: TlsState,
	role: TlsRole,
	// Session ID for this session
	session_id: Option<[u8; 32]>,
	// Changed cipher spec
	changed_cipher_spec: bool,
	// Handshake secret, Master secret
	// Early secret is computed right before HS
	// TLS standard: Secrets should not be stored unnecessarily
	latest_secret: Option<Vec<u8, U64>>,
	// Hash functions needed
	hash: Hash,
	// Ephemeral secret for ECDHE key exchange
	ecdhe_secret: Option<EphemeralSecret>,
	// Block ciphers for client & server
	client_cipher: Option<Cipher>,
	server_cipher: Option<Cipher>,
	// Traffic secret for client & server
	// Keeping traffic secret for key re-computation
	client_traffic_secret: Option<Vec<u8, U64>>,
	server_traffic_secret: Option<Vec<u8, U64>>,
	// Nonce (IV) for client & server
	// Always 12 bytes long
	client_nonce: Option<Vec<u8, U12>>,
	server_nonce: Option<Vec<u8, U12>>,
}

impl Session {
	pub(crate) fn new(role: TlsRole) -> Self {
		let hash = Hash::Undetermined {
			sha256: Sha256::new(),
			sha384: Sha384::new(),
		};
		Self {
			state: TlsState::START,
			role,
			session_id: None,
			changed_cipher_spec: false,
			latest_secret: None,
			hash,
			ecdhe_secret: None,
			client_cipher: None,
			server_cipher: None,
			client_traffic_secret: None,
			server_traffic_secret: None,
			client_nonce: None,
			server_nonce: None,
		}
	}

	// State transition from START to WAIT_SH
	pub(crate) fn client_update_for_ch(
		&mut self,
		ecdhe_secret: EphemeralSecret,
		session_id: [u8; 32],
		ch_slice: &[u8]
	) {
		// Handle inappropriate call to move state
		if self.state != TlsState::START || self.role != TlsRole::Client {
			todo!()
		}
		self.ecdhe_secret = Some(ecdhe_secret);
		self.session_id = Some(session_id);
		self.hash.update(ch_slice);
		self.state = TlsState::WAIT_SH;
	}

	// State transition from WAIT_SH to WAIT_EE
	pub(crate) fn client_update_for_sh(
		&mut self,
		cipher_suite: CipherSuite,
		encoded_point: EncodedPoint,
		sh_slice: &[u8]
	) {
		// Handle inappropriate call to move state
		if self.state != TlsState::WAIT_SH || self.role != TlsRole::Client {
			todo!()
		}
		// Generate ECDHE shared secret
		// Remove private secret
		let ecdhe_shared_secret =
			self.ecdhe_secret
				.take()
				.unwrap()
				.diffie_hellman(&encoded_point)
				.unwrap();

		// Generate Handshake secret
		match cipher_suite {
			CipherSuite::TLS_AES_128_GCM_SHA256 |
			CipherSuite::TLS_CHACHA20_POLY1305_SHA256 |
			CipherSuite::TLS_AES_128_CCM_SHA256 => {
				// Select 1 hash function, then update the hash
				self.hash = Hash::select_sha256(self.hash.clone());
				self.hash.update(sh_slice);

				// Find early secret in terms wrapped in HKDF
				let empty_psk: GenericArray<u8, <Sha256 as FixedOutput>::OutputSize> = Default::default();
				let early_secret_hkdf =
					Hkdf::<Sha256>::new(None, &empty_psk);

				// Find handshake secret
				let empty_hash = Sha256::new().chain("");
				let derived_secret = derive_secret(
					&early_secret_hkdf,
					"derived",
					empty_hash
				);

				let (handshake_secret, handshake_secret_hkdf) =
					Hkdf::<Sha256>::extract(
						Some(&derived_secret),
						ecdhe_shared_secret.as_bytes()
					);

				// Store the handshake secret
				self.latest_secret.replace(
					Vec::from_slice(&handshake_secret)
						.unwrap()
				);

				let client_handshake_traffic_secret = derive_secret(
					&handshake_secret_hkdf,
					"c hs traffic",
					self.hash.get_sha256_clone()
				);

				let server_handshake_traffic_secret = derive_secret(
					&handshake_secret_hkdf,
					"s hs traffic",
					self.hash.get_sha256_clone()
				);

				let client_handshake_traffic_secret_hkdf = Hkdf::<Sha256>::from_prk(&client_handshake_traffic_secret).unwrap();
				let server_handshake_traffic_secret_hkdf = Hkdf::<Sha256>::from_prk(&server_handshake_traffic_secret).unwrap();

				// Prepare holder for key and IV
				let client_handshake_key: Vec<u8, U64> = {
					let mut client_handshake_key_holder: Vec<u8, U64> = match cipher_suite {
						// 16 bytes key size
						CipherSuite::TLS_AES_128_GCM_SHA256 |
						CipherSuite::TLS_AES_128_CCM_SHA256 => {
							Vec::from_slice(&[0; 16]).unwrap()
						},
						// 32 bytes key size
						CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
							Vec::from_slice(&[0; 32]).unwrap()
						},
						// Not using Sha256 (AES_GCM_256) / not supported (CCM_8)
						_ => unreachable!()
					};
					hkdf_expand_label(
						&client_handshake_traffic_secret_hkdf,
						"key",
						"",
						&mut client_handshake_key_holder
					);
					client_handshake_key_holder
				};

				let client_handshake_iv: Vec<u8, U12> = {
					let mut client_handshake_iv_holder = Vec::from_slice(&[0; 12]).unwrap();
					hkdf_expand_label(
						&client_handshake_traffic_secret_hkdf,
						"iv",
						"",
						&mut client_handshake_iv_holder
					);
					client_handshake_iv_holder
				};

				let server_handshake_key: Vec<u8, U64> = {
					let mut server_handshake_key_holder: Vec<u8, U64> = match cipher_suite {
						// 16 bytes key size
						CipherSuite::TLS_AES_128_GCM_SHA256 |
						CipherSuite::TLS_AES_128_CCM_SHA256 => {
							Vec::from_slice(&[0; 16]).unwrap()
						},
						// 32 bytes key size
						CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
							Vec::from_slice(&[0; 32]).unwrap()
						},
						// Not using Sha256 (AES_GCM_256) / not supported (CCM_8)
						_ => unreachable!()
					};
					hkdf_expand_label(
						&server_handshake_traffic_secret_hkdf,
						"key",
						"",
						&mut server_handshake_key_holder
					);
					server_handshake_key_holder
				};

				let server_handshake_iv: Vec<u8, U12> = {
					let mut server_handshake_iv_holder = Vec::from_slice(&[0; 12]).unwrap();
					hkdf_expand_label(
						&client_handshake_traffic_secret_hkdf,
						"iv",
						"",
						&mut server_handshake_iv_holder
					);
					server_handshake_iv_holder
				};

				// Store nonce
				self.client_nonce = Some(client_handshake_iv);
				self.server_nonce = Some(server_handshake_iv);

				// Construct cipher from key & IV for client & server
				// Store the ciphers
				match cipher_suite {
					CipherSuite::TLS_AES_128_GCM_SHA256 => {
						let client_handshake_cipher = Aes128Gcm::new(
							GenericArray::from_slice(&client_handshake_key)
						);
						let server_handshake_cipher = Aes128Gcm::new(
							GenericArray::from_slice(&server_handshake_key)
						);
						self.client_cipher = Some(
							Cipher::Aes128Gcm {
								aes128gcm: client_handshake_cipher
							}
						);
						self.server_cipher = Some(
							Cipher::Aes128Gcm {
								aes128gcm: server_handshake_cipher
							}
						);
					},
					CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
						let client_handshake_cipher = ChaCha20Poly1305::new(
							GenericArray::from_slice(&client_handshake_key)
						);
						let server_handshake_cipher = ChaCha20Poly1305::new(
							GenericArray::from_slice(&server_handshake_key)
						);
						self.client_cipher = Some(
							Cipher::Chacha20poly1305 {
								chacha20poly1305: client_handshake_cipher
							}
						);
						self.server_cipher = Some(
							Cipher::Chacha20poly1305 {
								chacha20poly1305: server_handshake_cipher
							}
						);
					},
					CipherSuite::TLS_AES_128_CCM_SHA256 => {
						let client_handshake_cipher = Aes128Ccm::new(
							GenericArray::from_slice(&client_handshake_key)
						);
						let server_handshake_cipher = Aes128Ccm::new(
							GenericArray::from_slice(&server_handshake_key)
						);
						self.client_cipher = Some(
							Cipher::Ccm {
								ccm: client_handshake_cipher
							}
						);
						self.server_cipher = Some(
							Cipher::Ccm {
								ccm: server_handshake_cipher
							}
						);
					},
					_ => unreachable!()
				}
			}
			CipherSuite::TLS_AES_256_GCM_SHA384 => {
				// Select 1 hash function, then update the hash
				self.hash = Hash::select_sha384(self.hash.clone());
				self.hash.update(sh_slice);

				// Find early secret in terms wrapped in HKDF
				let empty_psk: GenericArray<u8, <Sha384 as FixedOutput>::OutputSize> = Default::default();
				let early_secret_hkdf =
					Hkdf::<Sha384>::new(None, &empty_psk);

				// Find handshake secret
				let empty_hash = Sha384::new().chain("");
				let derived_secret = derive_secret(
					&early_secret_hkdf,
					"derived",
					empty_hash
				);

				let (handshake_secret, handshake_secret_hkdf) =
					Hkdf::<Sha384>::extract(
						Some(&derived_secret),
						ecdhe_shared_secret.as_bytes()
					);

				// Store the handshake secret
				self.latest_secret.replace(
					Vec::from_slice(&handshake_secret)
						.unwrap()
				);

				let client_handshake_traffic_secret = derive_secret(
					&handshake_secret_hkdf,
					"c hs traffic",
					self.hash.get_sha384_clone()
				);

				let server_handshake_traffic_secret = derive_secret(
					&handshake_secret_hkdf,
					"s hs traffic",
					self.hash.get_sha384_clone()
				);

				let client_handshake_traffic_secret_hkdf = Hkdf::<Sha384>::from_prk(&client_handshake_traffic_secret).unwrap();
				let server_handshake_traffic_secret_hkdf = Hkdf::<Sha384>::from_prk(&server_handshake_traffic_secret).unwrap();

				// Prepare holder for key and IV
				let client_handshake_key: Vec<u8, U64> = {
					// 32 bytes key size
					let mut client_handshake_key_holder: Vec<u8, U64> =
						Vec::from_slice(&[0; 32]).unwrap();

					hkdf_expand_label(
						&client_handshake_traffic_secret_hkdf,
						"key",
						"",
						&mut client_handshake_key_holder
					);
					client_handshake_key_holder
				};

				let client_handshake_iv: Vec<u8, U12> = {
					let mut client_handshake_iv_holder = Vec::from_slice(&[0; 12]).unwrap();
					hkdf_expand_label(
						&client_handshake_traffic_secret_hkdf,
						"iv",
						"",
						&mut client_handshake_iv_holder
					);
					client_handshake_iv_holder
				};

				let server_handshake_key: Vec<u8, U64> = {
					// 32 bytes key size
					let mut server_handshake_key_holder: Vec<u8, U64> =
						Vec::from_slice(&[0; 32]).unwrap();

					hkdf_expand_label(
						&server_handshake_traffic_secret_hkdf,
						"key",
						"",
						&mut server_handshake_key_holder
					);
					server_handshake_key_holder
				};

				let server_handshake_iv: Vec<u8, U12> = {
					let mut server_handshake_iv_holder = Vec::from_slice(&[0; 12]).unwrap();
					hkdf_expand_label(
						&client_handshake_traffic_secret_hkdf,
						"iv",
						"",
						&mut server_handshake_iv_holder
					);
					server_handshake_iv_holder
				};

				// Store nonce
				self.client_nonce = Some(client_handshake_iv);
				self.server_nonce = Some(server_handshake_iv);

				let client_handshake_cipher = Aes256Gcm::new(
					GenericArray::from_slice(&client_handshake_key)
				);
				let server_handshake_cipher = Aes256Gcm::new(
					GenericArray::from_slice(&server_handshake_key)
				);
				self.client_cipher = Some(
					Cipher::Aes256Gcm {
						aes256gcm: client_handshake_cipher
					}
				);
				self.server_cipher = Some(
					Cipher::Aes256Gcm {
						aes256gcm: server_handshake_cipher
					}
				);

			}
			CipherSuite::TLS_AES_128_CCM_8_SHA256 => {
				unreachable!()
			}
		}
		self.state = TlsState::WAIT_EE;
	}

	pub(crate) fn client_update_for_ee(&mut self) {
		self.state = TlsState::WAIT_CERT_CR;
	}

	pub(crate) fn verify_session_id_echo(&self, session_id_echo: &[u8]) -> bool {
		if let Some(session_id_inner) = self.session_id {
			session_id_inner == session_id_echo
		} else {
			false
		}
	}

	pub(crate) fn get_tls_state(&self) -> TlsState {
		self.state
	}

	pub(crate) fn has_completed_handshake(&self) -> bool {
		self.state == TlsState::CONNECTED
	}

	pub(crate) fn receive_change_cipher_spec(&mut self) {
		self.changed_cipher_spec = true;
	}

	pub(crate) fn encrypt_in_place(
		&self,
		associated_data: &[u8],
		buffer: &mut dyn Buffer
	) -> Result<(), Error> {
		let (nonce, cipher): (&Vec<u8, U12>, &Cipher) = match self.role {
			TlsRole::Client => {(
				self.client_nonce.as_ref().unwrap(),
				self.client_cipher.as_ref().unwrap()
			)},
			TlsRole::Server => {(
				self.server_nonce.as_ref().unwrap(),
				self.server_cipher.as_ref().unwrap()
			)},
		};
		cipher.encrypt_in_place(
			&GenericArray::from_slice(nonce),
			associated_data,
			buffer
		)
	}

	pub(crate) fn decrypt_in_place(
		&self,
		associated_data: &[u8],
		buffer: &mut dyn Buffer
	) -> Result<(), Error> {
		let (nonce, cipher): (&Vec<u8, U12>, &Cipher) = match self.role {
			TlsRole::Client => {(
				self.client_nonce.as_ref().unwrap(),
				self.client_cipher.as_ref().unwrap()
			)},
			TlsRole::Server => {(
				self.server_nonce.as_ref().unwrap(),
				self.server_cipher.as_ref().unwrap()
			)},
		};
		cipher.decrypt_in_place(
			&GenericArray::from_slice(nonce),
			associated_data,
			buffer
		)
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum TlsRole {
	Client,
	Server,
}

#[derive(Debug, Clone)]
pub(crate) enum Hash {
	Undetermined {
		sha256: Sha256,
		sha384: Sha384,
	},
	Sha256 {
		sha256: Sha256
	},
	Sha384 {
		sha384: Sha384
	},
}

impl Hash {
	pub(crate) fn update(&mut self, data: &[u8]) {
		match self {
			Self::Undetermined { sha256, sha384 } => {
				sha256.update(data);
				sha384.update(data);
			},
			Self::Sha256 { sha256 } => {
				sha256.update(data);
			},
			Self::Sha384 { sha384 } => {
				sha384.update(data);
			},
		}
	}

	pub(crate) fn select_sha256(self) -> Self {
		match self {
			Self::Undetermined { sha256, sha384 } => {
				Self::Sha256 {
					sha256
				}
			},
			_ => unreachable!()
		}
	}

	pub(crate) fn select_sha384(self) -> Self {
		match self {
			Self::Undetermined { sha256, sha384 } => {
				Self::Sha384 {
					sha384
				}
			},
			_ => unreachable!()
		}
	}

	pub(crate) fn get_sha256_clone(&mut self) -> Sha256 {
		if let Self::Sha256 { sha256 } = self {
			sha256.clone()
		} else {
			unreachable!()
		}
	}

	pub(crate) fn get_sha384_clone(&mut self) -> Sha384 {
		if let Self::Sha384 { sha384 } = self {
			sha384.clone()
		} else {
			unreachable!()
		}
	}
}

pub(crate) enum Cipher {
	Aes128Gcm {
		aes128gcm: Aes128Gcm
	},
	Aes256Gcm {
		aes256gcm: Aes256Gcm
	},
	Chacha20poly1305 {
		chacha20poly1305: ChaCha20Poly1305
	},
	Ccm {
		ccm: Aes128Ccm
	},
}

impl Cipher {
	pub(crate) fn encrypt_in_place(
		&self,
		nonce: &GenericArray<u8, U12>,
		associated_data: &[u8],
		buffer: &mut dyn Buffer
	) -> Result<(), Error> {
		match self {
			Cipher::Aes128Gcm { aes128gcm } => {
				aes128gcm.encrypt_in_place(nonce, associated_data, buffer)
			},
			Cipher::Aes256Gcm { aes256gcm } => {
				aes256gcm.encrypt_in_place(nonce, associated_data, buffer)
			},
			Cipher::Chacha20poly1305 { chacha20poly1305 } => {
				chacha20poly1305.encrypt_in_place(nonce, associated_data, buffer)
			},
			Cipher::Ccm { ccm } => {
				ccm.encrypt_in_place(nonce, associated_data, buffer)
			}
		}.map_err(|_| Error::EncryptionError)
	}

	pub(crate) fn decrypt_in_place(
		&self,
		nonce: &GenericArray<u8, U12>,
		associated_data: &[u8],
		buffer: &mut dyn Buffer
	) -> Result<(), Error> {
		match self {
			Cipher::Aes128Gcm { aes128gcm } => {
				aes128gcm.decrypt_in_place(nonce, associated_data, buffer)
			},
			Cipher::Aes256Gcm { aes256gcm } => {
				aes256gcm.decrypt_in_place(nonce, associated_data, buffer)
			},
			Cipher::Chacha20poly1305 { chacha20poly1305 } => {
				chacha20poly1305.decrypt_in_place(nonce, associated_data, buffer)
			},
			Cipher::Ccm { ccm } => {
				ccm.decrypt_in_place(nonce, associated_data, buffer)
			}
		}.map_err(|_| Error::DecryptionError)
	}
}