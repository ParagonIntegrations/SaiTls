use p256::{ EncodedPoint, ecdh::EphemeralSecret };
use heapless::{ Vec, consts::* };
use sha2::{ Digest, Sha256, Sha384, Sha512, digest::FixedOutput };
use aes_gcm::{ Aes128Gcm, Aes256Gcm, aes::Aes128 };
use aes_gcm::{ AeadInPlace, NewAead, aead::Buffer };
use chacha20poly1305::ChaCha20Poly1305;
use ccm::Ccm;
use hkdf::Hkdf;
use generic_array::GenericArray;
use byteorder::{ByteOrder, NetworkEndian, BigEndian};
use rsa::{RSAPublicKey, PublicKey, PaddingScheme, Hash as RSAHash};
use hmac::{ Hmac, Mac, NewMac };

use rand_core::RngCore;

use core::convert::AsRef;
use core::cell::RefCell;

use crate::tls::TlsState;
use crate::tls_packet::CipherSuite;
use crate::key::*;
use crate::tls_packet::SignatureScheme;
use crate::Error;
use crate::fake_rng::FakeRandom;

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
    // Sequence number: Start from 0, 64 bits
    // Increment by one per record processed (read OR write)
    // Reset to 0 on rekey AND key exchange
    // TODO: Force rekey if sequence_number need to wrap
    sequence_number: u64,
    // Certificate public key
    // For Handling CertificateVerify
    cert_rsa_public_key: Option<RSAPublicKey>,
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
            sequence_number: 0,
            cert_rsa_public_key: None
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
    // TODO: Memory allocation
    // It current dumps too much memory onto the stack on invocation
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
                    self.hash.get_sha256_clone().unwrap()
                );

                let server_handshake_traffic_secret = derive_secret(
                    &handshake_secret_hkdf,
                    "s hs traffic",
                    self.hash.get_sha256_clone().unwrap()
                );

                // Store client_handshake_traffic_secret and
                // server_handshake_traffic_secret
                // Initial values of both secrets don't matter
                self.client_traffic_secret.replace(
                    Vec::from_slice(&client_handshake_traffic_secret).unwrap()
                );
                self.server_traffic_secret.replace(
                    Vec::from_slice(&server_handshake_traffic_secret).unwrap()
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
                        &server_handshake_traffic_secret_hkdf,
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
            },
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
                    self.hash.get_sha384_clone().unwrap()
                );

                let server_handshake_traffic_secret = derive_secret(
                    &handshake_secret_hkdf,
                    "s hs traffic",
                    self.hash.get_sha384_clone().unwrap()
                );

                // Store client_handshake_traffic_secret and
                // server_handshake_traffic_secret
                // Initial values of both secrets don't matter
                self.client_traffic_secret.replace(
                    Vec::from_slice(&client_handshake_traffic_secret).unwrap()
                );
                self.server_traffic_secret.replace(
                    Vec::from_slice(&server_handshake_traffic_secret).unwrap()
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
                        &server_handshake_traffic_secret_hkdf,
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

            },
            CipherSuite::TLS_AES_128_CCM_8_SHA256 => {
                unreachable!()
            }
        };
        self.state = TlsState::WAIT_EE;

        // Key exchange occurred, set seq_num to 0.
        self.sequence_number = 0;
    }

    pub(crate) fn client_update_for_ee(&mut self, ee_slice: &[u8]) {
        self.hash.update(ee_slice);
        self.state = TlsState::WAIT_CERT_CR;
    }

    pub(crate) fn client_update_for_wait_cert_cr(
        &mut self,
        cert_slice: &[u8],
        cert_rsa_public_key: RSAPublicKey
    ) {
        self.hash.update(cert_slice);
        self.cert_rsa_public_key.replace(cert_rsa_public_key);
        self.state = TlsState::WAIT_CV;
    }

    pub(crate) fn client_update_for_wait_cv(
        &mut self,
        cert_verify_slice: &[u8],
        signature_algorithm: SignatureScheme,
        signature: &[u8]
    )
    {
        // Clone the transcript hash from ClientHello all the way to Certificate
        let transcript_hash: Vec<u8, U64> = if let Ok(sha256) = self.hash.get_sha256_clone() {
            Vec::from_slice(&sha256.finalize()).unwrap()
        } else if let Ok(sha384) = self.hash.get_sha384_clone() {
            Vec::from_slice(&sha384.finalize()).unwrap()
        } else {
            unreachable!()
        };

        // Handle Ed25519 and p256 separately
        // These 2 algorithms have a mandated hash function
        if signature_algorithm == SignatureScheme::ecdsa_secp256r1_sha256 ||
            signature_algorithm == SignatureScheme::ed25519
        {
            todo!()
        }

        // Get verification hash, and verify the signature
        use crate::tls_packet::SignatureScheme::*;

        let get_rsa_padding_scheme = |sig_alg: SignatureScheme| -> PaddingScheme {
            match signature_algorithm {
                rsa_pkcs1_sha256 => {
                    PaddingScheme::new_pkcs1v15_sign(Some(RSAHash::SHA2_256))
                },
                rsa_pkcs1_sha384 => {
                    PaddingScheme::new_pkcs1v15_sign(Some(RSAHash::SHA2_384))
                },
                rsa_pkcs1_sha512 => {
                    PaddingScheme::new_pkcs1v15_sign(Some(RSAHash::SHA2_512))
                },
                rsa_pss_rsae_sha256 | rsa_pss_pss_sha256 => {
                    PaddingScheme::new_pss::<Sha256, FakeRandom>(FakeRandom{})
                },
                rsa_pss_rsae_sha384 | rsa_pss_pss_sha384 => {
                    PaddingScheme::new_pss::<Sha384, FakeRandom>(FakeRandom{})
                },
                rsa_pss_rsae_sha512 | rsa_pss_pss_sha512 => {
                    PaddingScheme::new_pss::<Sha512, FakeRandom>(FakeRandom{})
                },
                _ => unreachable!()
            }
        };

        match signature_algorithm {
            rsa_pkcs1_sha256 | rsa_pss_rsae_sha256 | rsa_pss_pss_sha256 => {
                let verify_hash = Sha256::new()
                    .chain(&[0x20; 64])
                    .chain("TLS 1.3, server CertificateVerify")
                    .chain(&[0])
                    .chain(&transcript_hash)
                    .finalize();
                let padding = get_rsa_padding_scheme(signature_algorithm);
                let verify_result = self.cert_rsa_public_key.take().unwrap().verify(
                    padding, &verify_hash, signature
                );
                log::info!("Algorithm {:?} Certificate verify: {:?}", signature_algorithm, verify_result);
                if verify_result.is_err() {
                    todo!()
                }
            },
            rsa_pkcs1_sha384 | rsa_pss_rsae_sha384 | rsa_pss_pss_sha384 => {
                let verify_hash = Sha384::new()
                    .chain(&[0x20; 64])
                    .chain("TLS 1.3, server CertificateVerify")
                    .chain(&[0])
                    .chain(&transcript_hash)
                    .finalize();
                let padding = get_rsa_padding_scheme(signature_algorithm);
                let verify_result = self.cert_rsa_public_key.take().unwrap().verify(
                    padding, &verify_hash, signature
                );
                log::info!("Algorithm {:?} Certificate verify: {:?}", signature_algorithm, verify_result);
                if verify_result.is_err() {
                    todo!()
                }
            },
            rsa_pkcs1_sha512 | rsa_pss_rsae_sha512 | rsa_pss_pss_sha512 => {
                let verify_hash = Sha512::new()
                    .chain(&[0x20; 64])
                    .chain("TLS 1.3, server CertificateVerify")
                    .chain(&[0])
                    .chain(&transcript_hash)
                    .finalize();
                let padding = get_rsa_padding_scheme(signature_algorithm);
                let verify_result = self.cert_rsa_public_key.take().unwrap().verify(
                    padding, &verify_hash, signature
                );
                if verify_result.is_err() {
                    todo!()
                }
            },
            _ => unreachable!()
        };

        // Usual procedures: update hash
        self.hash.update(cert_verify_slice);

        // At last, update client state
        self.state = TlsState::WAIT_FINISHED;
    }

    pub(crate) fn client_update_for_wait_finished(
        &mut self,
        server_finished_slice: &[u8],
        server_verify_data: &[u8]
    )
    {
        // Take hash from session
        if let Ok(sha256) = self.hash.get_sha256_clone() {
            let hkdf = Hkdf::<Sha256>::from_prk(
                self.server_traffic_secret.as_ref().unwrap()
            ).unwrap();

            // Compute finished_key
            let mut okm: GenericArray::<u8, <Sha256 as Digest>::OutputSize> = 
                Default::default();
            hkdf_expand_label(&hkdf, "finished", "", &mut okm);

            // Get transcript hash
            let transcript_hash = sha256.finalize();

            // Compute verify_data
            // let computed_verify_data = Sha256::new()
            //     .chain(&okm)
            //     .chain(&transcript_hash)
            //     .finalize();
            let mut hmac = Hmac::<Sha256>::new_varkey(&okm).unwrap();
            hmac.update(&transcript_hash);
            log::info!("HMAC: {:?}", hmac);
            log::info!("Received data: {:?}", server_verify_data);
            hmac.verify(server_verify_data).unwrap();

        } else if let Ok(sha384) = self.hash.get_sha384_clone() {
            let hkdf = Hkdf::<Sha384>::from_prk(
                self.server_traffic_secret.as_ref().unwrap()
            ).unwrap();

            // Compute finished_key
            let mut okm: GenericArray::<u8, <Sha384 as Digest>::OutputSize> =
                Default::default();
            hkdf_expand_label(&hkdf, "finished", "", &mut okm);

            // Get transcript hash
            let transcript_hash = sha384.finalize();

            // Compute verify_data
            // let computed_verify_data = Sha384::new()
            //     .chain(&okm)
            //     .chain(&transcript_hash)
            //     .finalize();
            // log::info!("Computed data: {:?}", computed_verify_data);
            // log::info!("Received data: {:?}", server_verify_data);
            // assert_eq!(computed_verify_data.as_slice(), server_verify_data);
            let mut hmac = Hmac::<Sha384>::new_varkey(&okm).unwrap();
            hmac.update(&transcript_hash);
            log::info!("HMAC: {:?}", hmac);
            log::info!("Received data: {:?}", server_verify_data);
            hmac.verify(server_verify_data).unwrap();

        } else {
            unreachable!()
        };

        // Usual procedures: update hash
        self.hash.update(server_finished_slice);

        // At last, update client state
        self.state = TlsState::SERVER_CONNECTED;
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

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = self.sequence_number.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        cipher.encrypt_in_place(
            &GenericArray::from_slice(&processed_nonce),
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
            TlsRole::Server => {(
                self.client_nonce.as_ref().unwrap(),
                self.client_cipher.as_ref().unwrap()
            )},
            TlsRole::Client => {(
                self.server_nonce.as_ref().unwrap(),
                self.server_cipher.as_ref().unwrap()
            )},
        };

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = self.sequence_number.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        cipher.decrypt_in_place(
            &GenericArray::from_slice(&processed_nonce),
            associated_data,
            buffer
        )
    }

    pub(crate) fn increment_sequence_number(&mut self) {
        self.sequence_number += 1;
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

    pub(crate) fn get_sha256_clone(&mut self) -> Result<Sha256, ()> {
        if let Self::Sha256 { sha256 } = self {
            Ok(sha256.clone())
        } else {
            Err(())
        }
    }

    pub(crate) fn get_sha384_clone(&mut self) -> Result<Sha384, ()> {
        if let Self::Sha384 { sha384 } = self {
            Ok(sha384.clone())
        } else {
            Err(())
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