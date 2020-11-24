use p256::{ EncodedPoint, ecdh::EphemeralSecret, ecdsa::signature::DigestVerifier };
use heapless::{ Vec, consts::* };
use sha2::{ Digest, Sha256, Sha384, Sha512, digest::FixedOutput };
use aes_gcm::{ Aes128Gcm, Aes256Gcm, aes::Aes128 };
use aes_gcm::{ AeadInPlace, NewAead, aead::Buffer };
use chacha20poly1305::ChaCha20Poly1305;
use ccm::Ccm;
use hkdf::Hkdf;
use generic_array::GenericArray;
use byteorder::{ByteOrder, NetworkEndian};
use rsa::{RSAPublicKey, PublicKey, PaddingScheme, Hash as RSAHash};
use hmac::{ Hmac, Mac, NewMac };
use smoltcp::wire::IpEndpoint;

use crate::tls::TlsState;
use crate::tls_packet::CipherSuite;
use crate::key::*;
use crate::tls_packet::SignatureScheme;
use crate::Error;
use crate::fake_rng::{FakeRandom, OneTimeRandom};

use core::convert::TryFrom;

type Aes128Ccm = Ccm<Aes128, U16, U12>;

pub(crate) struct Session<'a> {
    state: TlsState,
    role: TlsRole,
    // Local and remote endpoints of the socket
    // TCP socket does store these 2 information and it is gettable
    // However, upon invokation of `reset`, these endpoints are wiped out
    // Should TLS socket requires TCP socket to restart, we need these info
    local_endpoint: IpEndpoint,
    remote_endpoint: IpEndpoint,
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
    ecdhe_secret: Option<(EphemeralSecret, x25519_dalek::EphemeralSecret)>,
    // Block ciphers for client & server
    client_handshake_cipher: Option<Cipher>,
    server_handshake_cipher: Option<Cipher>,
    client_application_cipher: Option<Cipher>,
    server_application_cipher: Option<Cipher>,
    // Traffic secret for client & server during handshake
    // Keeping traffic secret for key re-computation
    client_handshake_traffic_secret: Option<Vec<u8, U64>>,
    server_handshake_traffic_secret: Option<Vec<u8, U64>>,
    // Traffic secret for client & server during app data transfer
    // Keeping traffic secret for key re-computation
    client_application_traffic_secret: Option<Vec<u8, U64>>,
    server_application_traffic_secret: Option<Vec<u8, U64>>,
    // Nonce (IV) for client & server
    // Always 12 bytes long
    client_handshake_nonce: Option<Vec<u8, U12>>,
    server_handshake_nonce: Option<Vec<u8, U12>>,
    client_application_nonce: Option<Vec<u8, U12>>,
    server_application_nonce: Option<Vec<u8, U12>>,
    // Sequence number: Start from 0, 64 bits
    // Increment by one per record processed (read OR write)
    // Reset to 0 on rekey AND key exchange
    // TODO: Force rekey if sequence number need to wrap (very low priority)
    client_sequence_number: u64,
    pub server_sequence_number: u64,
    // Certificate public key
    // For Handling CertificateVerify
    cert_public_key: Option<CertificatePublicKey>,
    // Client certificate and its private key
    cert_private_key: Option<(CertificatePrivateKey, alloc::vec::Vec<&'a [u8]>)>,
    // Flag for noting the need to send client certificate
    // Client must cent Certificate extension iff server requested it
    need_send_client_cert: bool,
    client_cert_verify_sig_alg: Option<crate::tls_packet::SignatureScheme>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(role: TlsRole, certificate_with_key: Option<(
        CertificatePrivateKey, alloc::vec::Vec<&'a [u8]>
    )>) -> Self {
        let hash = Hash::Undetermined {
            sha256: Sha256::new(),
            sha384: Sha384::new(),
        };
        Self {
            state: TlsState::START,
            role,
            local_endpoint: IpEndpoint::default(),
            remote_endpoint: IpEndpoint::default(),
            session_id: None,
            changed_cipher_spec: false,
            latest_secret: None,
            hash,
            ecdhe_secret: None,
            client_handshake_cipher: None,
            server_handshake_cipher: None,
            client_application_cipher: None,
            server_application_cipher: None,
            client_handshake_traffic_secret: None,
            server_handshake_traffic_secret: None,
            client_application_traffic_secret: None,
            server_application_traffic_secret: None,
            client_handshake_nonce: None,
            server_handshake_nonce: None,
            client_application_nonce: None,
            server_application_nonce: None,
            client_sequence_number: 0,
            server_sequence_number: 0,
            cert_public_key: None,
            cert_private_key: certificate_with_key,
            need_send_client_cert: false,
            client_cert_verify_sig_alg: None
        }
    }

    pub(crate) fn connect(
        &mut self,
        remote_endpoint: IpEndpoint,
        local_endpoint: IpEndpoint
    ) {
        self.role = TlsRole::Client;
        self.state = TlsState::START;
        self.local_endpoint = local_endpoint;
        self.remote_endpoint = remote_endpoint;
    }

    // State transition from START to WAIT_SH
    pub(crate) fn client_update_for_ch(
        &mut self,
        ecdhe_secret: EphemeralSecret,
        x25519_secret: x25519_dalek::EphemeralSecret,
        session_id: [u8; 32],
        ch_slice: &[u8]
    ) {
        // Handle inappropriate call to move state
        if self.state != TlsState::START || self.role != TlsRole::Client {
            todo!()
        }
        self.ecdhe_secret = Some((ecdhe_secret, x25519_secret));
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
        encoded_point: Option<EncodedPoint>,
        x25519_shared: Option<x25519_dalek::PublicKey>,
        sh_slice: &[u8]
    ) {
        // Handle inappropriate call to move state
        if self.state != TlsState::WAIT_SH || self.role != TlsRole::Client {
            todo!()
        }
       
        let mut shared_secret_bytes: [u8; 32] = [0; 32];
        if encoded_point.is_some() {
            let p256_shared_secret =
                self.ecdhe_secret
                    .take()
                    .unwrap()
                    .0
                    .diffie_hellman(&encoded_point.unwrap())
                    .unwrap();
            shared_secret_bytes.clone_from_slice(p256_shared_secret.as_bytes());
        } else if x25519_shared.is_some() {
            let x25519_shared_secret =
                self.ecdhe_secret
                    .take()
                    .unwrap()
                    .1
                    .diffie_hellman(&x25519_shared.unwrap());
            shared_secret_bytes.clone_from_slice(x25519_shared_secret.as_bytes());
        } else {
            todo!()
        }

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
                        &shared_secret_bytes
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
                self.client_handshake_traffic_secret.replace(
                    Vec::from_slice(&client_handshake_traffic_secret).unwrap()
                );
                self.server_handshake_traffic_secret.replace(
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
                self.client_handshake_nonce = Some(client_handshake_iv);
                self.server_handshake_nonce = Some(server_handshake_iv);

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
                        self.client_handshake_cipher = Some(
                            Cipher::Aes128Gcm {
                                aes128gcm: client_handshake_cipher
                            }
                        );
                        self.server_handshake_cipher = Some(
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
                        self.client_handshake_cipher = Some(
                            Cipher::Chacha20poly1305 {
                                chacha20poly1305: client_handshake_cipher
                            }
                        );
                        self.server_handshake_cipher = Some(
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
                        self.client_handshake_cipher = Some(
                            Cipher::Ccm {
                                ccm: client_handshake_cipher
                            }
                        );
                        self.server_handshake_cipher = Some(
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
                        &shared_secret_bytes
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
                self.client_handshake_traffic_secret.replace(
                    Vec::from_slice(&client_handshake_traffic_secret).unwrap()
                );
                self.server_handshake_traffic_secret.replace(
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
                self.client_handshake_nonce = Some(client_handshake_iv);
                self.server_handshake_nonce = Some(server_handshake_iv);

                let client_handshake_cipher = Aes256Gcm::new(
                    GenericArray::from_slice(&client_handshake_key)
                );
                let server_handshake_cipher = Aes256Gcm::new(
                    GenericArray::from_slice(&server_handshake_key)
                );
                self.client_handshake_cipher = Some(
                    Cipher::Aes256Gcm {
                        aes256gcm: client_handshake_cipher
                    }
                );
                self.server_handshake_cipher = Some(
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
        self.client_sequence_number = 0;
        self.server_sequence_number = 0;
    }

    pub(crate) fn client_update_for_ee(&mut self, ee_slice: &[u8]) {
        self.hash.update(ee_slice);
        self.state = TlsState::WAIT_CERT_CR;
    }

    pub(crate) fn client_update_for_certificate_request(
        &mut self,
        cert_request_slice: &[u8],
        signature_algorithms: &[crate::tls_packet::SignatureScheme]
    ) {
        self.hash.update(cert_request_slice);
        // Note the need of sending client certificate
        self.need_send_client_cert = true;
        // Determine the supplied client certificate indeed has an
        // acceptable signature algorithm
        let mut private_key_algorithm_acceptable = false;
        if let Some((private_key, _cert)) = &self.cert_private_key {
            if let CertificatePrivateKey::RSA {..} = private_key {
                for sig_alg in signature_algorithms.iter() {
                    use crate::tls_packet::SignatureScheme::*;
                    if *sig_alg == rsa_pkcs1_sha256
                        || *sig_alg == rsa_pkcs1_sha384
                        || *sig_alg == rsa_pkcs1_sha512
                        || *sig_alg == rsa_pss_rsae_sha256
                        || *sig_alg == rsa_pss_rsae_sha384
                        || *sig_alg == rsa_pss_rsae_sha512
                        || *sig_alg == rsa_pss_pss_sha256
                        || *sig_alg == rsa_pss_pss_sha384
                        || *sig_alg == rsa_pss_pss_sha512
                    {
                        private_key_algorithm_acceptable = true;
                        self.client_cert_verify_sig_alg.replace(*sig_alg);
                        break;
                    }
                }
            } else if let CertificatePrivateKey::ECDSA_SECP256R1_SHA256 {..}
                = private_key
            {
                for sig_alg in signature_algorithms.iter() {
                    use crate::tls_packet::SignatureScheme::*;
                    if *sig_alg == ecdsa_secp256r1_sha256
                    {
                        private_key_algorithm_acceptable = true;
                        self.client_cert_verify_sig_alg.replace(*sig_alg);
                        break;
                    }
                }
            } else if let CertificatePrivateKey::ED25519 {..} = private_key {
                for sig_alg in signature_algorithms.iter() {
                    use crate::tls_packet::SignatureScheme::*;
                    if *sig_alg == ed25519
                    {
                        private_key_algorithm_acceptable = true;
                        self.client_cert_verify_sig_alg.replace(*sig_alg);
                        break;
                    }
                }
            }
        }

        // Dump the private key and certificate if the other side will not take it
        if !private_key_algorithm_acceptable {
            self.cert_private_key.take();
        }

        log::info!("client key: {:?}", self.cert_private_key.is_some());

        // Move to the next state
        self.state = TlsState::WAIT_CERT;
    }

    pub(crate) fn client_update_for_wait_cert_cr(
        &mut self,
        cert_slice: &[u8],
        cert_public_key: CertificatePublicKey
    ) {
        self.hash.update(cert_slice);
        self.cert_public_key.replace(cert_public_key);
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
        if signature_algorithm == SignatureScheme::ecdsa_secp256r1_sha256 {
            let verify_hash = Sha256::new()
                .chain(&[0x20; 64])
                .chain("TLS 1.3, server CertificateVerify")
                .chain(&[0])
                .chain(&transcript_hash);
            let ecdsa_signature = p256::ecdsa::Signature::from_asn1(signature).unwrap();
            self.cert_public_key
                .take()
                .unwrap()
                .get_ecdsa_secp256r1_sha256_verify_key()
                .unwrap()
                .verify_digest(
                    verify_hash, &ecdsa_signature
                ).unwrap();

            // Usual procedures: update hash
            self.hash.update(cert_verify_slice);
            // At last, update client state
            self.state = TlsState::WAIT_FINISHED;
            return;
        }

        // ED25519 only accepts PureEdDSA implementation
        if signature_algorithm == SignatureScheme::ed25519 {
            // 64 bytes of 0x20
            // 33 bytes of text
            // 1 byte of 0
            // potentially 48 bytes of transcript hash
            // 146 bytes in total
            let mut verify_message: Vec<u8, U146> = Vec::new();
            verify_message.extend_from_slice(&[0x20; 64]).unwrap();
            verify_message.extend_from_slice(b"TLS 1.3, server CertificateVerify").unwrap();
            verify_message.extend_from_slice(&[0]).unwrap();
            verify_message.extend_from_slice(&transcript_hash).unwrap();
            let ed25519_signature = ed25519_dalek::Signature::try_from(
                signature
            ).unwrap();
            self.cert_public_key.take()
                .unwrap()
                .get_ed25519_public_key()
                .unwrap()
                .verify_strict(&verify_message, &ed25519_signature)
                .unwrap();
            
            // Usual procedures: update hash
            self.hash.update(cert_verify_slice);
            // At last, update client state
            self.state = TlsState::WAIT_FINISHED;
            return;
        }

        // Get verification hash, and verify the signature
        use crate::tls_packet::SignatureScheme::*;

        let get_rsa_padding_scheme = |sig_alg: SignatureScheme| -> PaddingScheme {
            match sig_alg {
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
                let verify_result = self.cert_public_key
                    .take()
                    .unwrap()
                    .get_rsa_public_key()
                    .unwrap()
                    .verify(
                        padding, &verify_hash, signature
                    );
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
                let verify_result = self.cert_public_key
                    .take()
                    .unwrap()
                    .get_rsa_public_key()
                    .unwrap()
                    .verify(
                        padding, &verify_hash, signature
                    );
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
                let verify_result = self.cert_public_key
                    .take()
                    .unwrap()
                    .get_rsa_public_key()
                    .unwrap()
                    .verify(
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
                self.server_handshake_traffic_secret.as_ref().unwrap()
            ).unwrap();

            // Compute finished_key
            let mut okm: GenericArray::<u8, <Sha256 as Digest>::OutputSize> = 
                Default::default();
            hkdf_expand_label(&hkdf, "finished", "", &mut okm);

            // Get transcript hash
            let transcript_hash = sha256.finalize();

            // Compute verify_data
            let mut hmac = Hmac::<Sha256>::new_varkey(&okm).unwrap();
            hmac.update(&transcript_hash);
            hmac.verify(server_verify_data).unwrap();

            // Update hash for key computation
            self.hash.update(server_finished_slice);

            // Derive application traffic secret, key, IV on client's side
            // 1. Derive secret from "Handshake Secret"
            let hkdf = Hkdf::<Sha256>::from_prk(
                // TLS requires the removal of secret if such secret is not of any use
                // Replace "latest_secret" with None
                self.latest_secret.as_ref().unwrap()
            ).unwrap();

            let empty_hash = Sha256::new().chain("");
            let derived_secret = derive_secret(&hkdf, "derived", empty_hash);

            // 2. HKDF-extract "Master Secret"
            let zero_ikm: GenericArray<u8, <Sha256 as FixedOutput>::OutputSize>
                = Default::default();
            let (master_secret, master_secret_hkdf) = Hkdf::<Sha256>::extract(
                Some(&derived_secret),
                &zero_ikm
            );

            // Replace latest secret with "master_secret"
            self.latest_secret.replace(
                Vec::from_slice(&master_secret).unwrap()
            );

            // 3. Get application traffic secret
            let client_application_traffic_secret = derive_secret(
                &master_secret_hkdf,
                "c ap traffic",
                self.hash.get_sha256_clone().unwrap()
            );

            let server_application_traffic_secret = derive_secret(
                &master_secret_hkdf,
                "s ap traffic",
                self.hash.get_sha256_clone().unwrap()
            );

            self.client_application_traffic_secret.replace(
                Vec::from_slice(&client_application_traffic_secret).unwrap()
            );
            self.server_application_traffic_secret.replace(
                Vec::from_slice(&server_application_traffic_secret).unwrap()
            );

            // 4. Replace cipher and IV
            let client_application_traffic_hkdf = Hkdf::<Sha256>::from_prk(
                &client_application_traffic_secret
            ).unwrap();
            let server_application_traffic_hkdf = Hkdf::<Sha256>::from_prk(
                &server_application_traffic_secret
            ).unwrap(); 

            // Init key and IV holders
            let cipher_suite = self.client_handshake_cipher.as_ref().unwrap().get_cipher_suite_type();

            let (mut client_key_holder, mut client_iv_holder,
                mut server_key_holder, mut server_iv_holder):
                (Vec::<u8, U64>, Vec::<u8, U12>, Vec::<u8, U64>, Vec::<u8, U12>) =
                match cipher_suite {
                CipherSuite::TLS_AES_128_GCM_SHA256 => {
                    (
                        Vec::from_slice(&[0; 16]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap(),
                        Vec::from_slice(&[0; 16]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap()
                    )
                },
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
                    (
                        Vec::from_slice(&[0; 32]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap(),
                        Vec::from_slice(&[0; 32]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap()
                    )
                },
                CipherSuite::TLS_AES_128_CCM_SHA256 => {
                    (
                        Vec::from_slice(&[0; 16]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap(),
                        Vec::from_slice(&[0; 16]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap()
                    )
                },
                // TLS_AES_128_CCM_8_SHA256 is not offered
                // TLS_AES_256_GCM_SHA384 should not have SHA256 as hash
                _ => unreachable!()
            };

            // Derive Key and IV for both server and client
            hkdf_expand_label(
                &client_application_traffic_hkdf,
                "key",
                "",
                &mut client_key_holder
            );
            hkdf_expand_label(
                &client_application_traffic_hkdf,
                "iv",
                "",
                &mut client_iv_holder
            );
            hkdf_expand_label(
                &server_application_traffic_hkdf,
                "key",
                "",
                &mut server_key_holder
            );
            hkdf_expand_label(
                &server_application_traffic_hkdf,
                "iv",
                "",
                &mut server_iv_holder
            );
            
            // Store IV/nonce
            self.client_application_nonce.replace(client_iv_holder);
            self.server_application_nonce.replace(server_iv_holder);

            // Instantiate new ciphers
            match cipher_suite {
                CipherSuite::TLS_AES_128_GCM_SHA256 => {
                    self.client_application_cipher.replace(
                        Cipher::Aes128Gcm {
                            aes128gcm: Aes128Gcm::new(
                                &GenericArray::from_slice(&client_key_holder)
                            )
                        }
                    );
                    self.server_application_cipher.replace(
                        Cipher::Aes128Gcm {
                            aes128gcm: Aes128Gcm::new(
                                &GenericArray::from_slice(&server_key_holder)
                            )
                        }
                    );
                },
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => {
                    self.client_application_cipher.replace(
                        Cipher::Chacha20poly1305 {
                            chacha20poly1305: ChaCha20Poly1305::new(
                                &GenericArray::from_slice(&client_key_holder)
                            )
                        }
                    );
                    self.server_application_cipher.replace(
                        Cipher::Chacha20poly1305 {
                            chacha20poly1305: ChaCha20Poly1305::new(
                                &GenericArray::from_slice(&server_key_holder)
                            )
                        }
                    );
                },
                CipherSuite::TLS_AES_128_CCM_SHA256 => {
                    self.client_application_cipher.replace(
                        Cipher::Ccm {
                            ccm: Aes128Ccm::new(
                                &GenericArray::from_slice(&client_key_holder)
                            )
                        }
                    );
                    self.server_application_cipher.replace(
                        Cipher::Ccm {
                            ccm: Aes128Ccm::new(
                                &GenericArray::from_slice(&server_key_holder)
                            )
                        }
                    );
                },
                _ => unreachable!()
            }

        } else if let Ok(sha384) = self.hash.get_sha384_clone() {
            let hkdf = Hkdf::<Sha384>::from_prk(
                self.server_handshake_traffic_secret.as_ref().unwrap()
            ).unwrap();

            // Compute finished_key
            let mut okm: GenericArray::<u8, <Sha384 as Digest>::OutputSize> =
                Default::default();
            hkdf_expand_label(&hkdf, "finished", "", &mut okm);

            // Get transcript hash
            let transcript_hash = sha384.finalize();

            // Compute verify_data using HMAC
            let mut hmac = Hmac::<Sha384>::new_varkey(&okm).unwrap();
            hmac.update(&transcript_hash);
            log::info!("HMAC: {:?}", hmac);
            log::info!("Received data: {:?}", server_verify_data);
            hmac.verify(server_verify_data).unwrap();

            // Update hash for key computation
            self.hash.update(server_finished_slice);

            // Derive application traffic secret, key, IV on client's side
            // 1. Derive secret from "Handshake Secret"
            let hkdf = Hkdf::<Sha384>::from_prk(
                self.latest_secret.as_ref().unwrap()
            ).unwrap();

            let empty_hash = Sha384::new().chain("");
            let derived_secret = derive_secret(&hkdf, "derived", empty_hash);

            // 2. HKDF-extract "Master Secret"
            let zero_ikm: GenericArray<u8, <Sha384 as FixedOutput>::OutputSize>
                = Default::default();
            let (master_secret, master_secret_hkdf) = Hkdf::<Sha384>::extract(
                Some(&derived_secret),
                &zero_ikm
            );

            // Replace latest secret with "master_secret"
            self.latest_secret.replace(
                Vec::from_slice(&master_secret).unwrap()
            );

            // 3. Get application traffic secret
            let client_application_traffic_secret = derive_secret(
                &master_secret_hkdf,
                "c ap traffic",
                self.hash.get_sha384_clone().unwrap()
            );

            let server_application_traffic_secret = derive_secret(
                &master_secret_hkdf,
                "s ap traffic",
                self.hash.get_sha384_clone().unwrap()
            );

            self.client_application_traffic_secret.replace(
                Vec::from_slice(&client_application_traffic_secret).unwrap()
            );
            self.server_application_traffic_secret.replace(
                Vec::from_slice(&server_application_traffic_secret).unwrap()
            );

            // 4. Replace cipher and IV
            let client_application_traffic_hkdf = Hkdf::<Sha384>::from_prk(
                &client_application_traffic_secret
            ).unwrap();
            let server_application_traffic_hkdf = Hkdf::<Sha384>::from_prk(
                &server_application_traffic_secret
            ).unwrap(); 

            // Init key and IV holders
            let cipher_suite = self.client_handshake_cipher.as_ref().unwrap().get_cipher_suite_type();

            let (mut client_key_holder, mut client_iv_holder,
                mut server_key_holder, mut server_iv_holder):
                (Vec::<u8, U64>, Vec::<u8, U12>, Vec::<u8, U64>, Vec::<u8, U12>) =
                match cipher_suite {
                CipherSuite::TLS_AES_256_GCM_SHA384 => {
                    (
                        Vec::from_slice(&[0; 32]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap(),
                        Vec::from_slice(&[0; 32]).unwrap(),
                        Vec::from_slice(&[0; 12]).unwrap()
                    )
                },
                // TLS_AES_128_CCM_8_SHA256 is not offered
                // Only TLS_AES_256_GCM_SHA384 should have SHA384 as hash
                _ => unreachable!()
            };

            // Derive Key and IV for both server and client
            hkdf_expand_label(
                &client_application_traffic_hkdf,
                "key",
                "",
                &mut client_key_holder
            );
            hkdf_expand_label(
                &client_application_traffic_hkdf,
                "iv",
                "",
                &mut client_iv_holder
            );
            hkdf_expand_label(
                &server_application_traffic_hkdf,
                "key",
                "",
                &mut server_key_holder
            );
            hkdf_expand_label(
                &server_application_traffic_hkdf,
                "iv",
                "",
                &mut server_iv_holder
            );
            
            // Store IV/nonce
            self.client_application_nonce.replace(client_iv_holder);
            self.server_application_nonce.replace(server_iv_holder);

            // Instantiate new ciphers
            match cipher_suite {
                CipherSuite::TLS_AES_256_GCM_SHA384 => {
                    self.client_application_cipher.replace(
                        Cipher::Aes256Gcm {
                            aes256gcm: Aes256Gcm::new(
                                &GenericArray::from_slice(&client_key_holder)
                            )
                        }
                    );
                    self.server_application_cipher.replace(
                        Cipher::Aes256Gcm {
                            aes256gcm: Aes256Gcm::new(
                                &GenericArray::from_slice(&server_key_holder)
                            )
                        }
                    );
                },
                _ => unreachable!()
            }

        } else {
            unreachable!()
        };
        // Hash was updated for key computation

        // At last, update client state
        self.state = TlsState::SERVER_CONNECTED;
    }

    pub(crate) fn client_update_for_certificate_in_server_connected(
        &mut self,
        client_certificate_slice: &[u8]
    )
    {
        // Sequence number is updated by send methods
        // No need to change state as client will send everything needed immediately
        self.hash.update(client_certificate_slice);
    }

    pub(crate) fn client_update_for_cert_verify_in_server_connected(
        &mut self,
        client_certificate_verify_slice: &[u8]
    )
    {
        // Sequence number is updated by send methods
        // No need to change state as client will send everything needed immediately
        self.hash.update(client_certificate_verify_slice);
    }


    pub(crate) fn client_update_for_server_connected(
        &mut self,
        client_finished_slice: &[u8]
    )
    {
        // Will change server & client key to application key,
        // Reset sequence number
        self.client_sequence_number = 0;
        self.server_sequence_number = 0;
        self.hash.update(client_finished_slice);
        self.state = TlsState::CONNECTED;
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

    pub(crate) fn get_local_endpoint(&self) -> IpEndpoint {
        self.local_endpoint
    }

    pub(crate) fn get_remote_endpoint(&self) -> IpEndpoint {
        self.remote_endpoint
    }

    pub(crate) fn has_completed_handshake(&self) -> bool {
        self.state == TlsState::CONNECTED
    }

    pub(crate) fn receive_change_cipher_spec(&mut self) {
        self.changed_cipher_spec = true;
    }

    pub(crate) fn need_to_send_client_certificate(&self) -> bool {
        self.need_send_client_cert
    }

    pub(crate) fn get_private_certificate_slices(&self) -> Option<&alloc::vec::Vec<&[u8]>> {
        if let Some((_, cert_vec)) = &self.cert_private_key {
            Some(cert_vec)
        } else {
            None
        }
    }

    pub(crate) fn get_client_certificate_verify_signature<R: rand_core::RngCore>(&self, rng: &mut R)
        -> (crate::tls_packet::SignatureScheme, alloc::vec::Vec<u8>) 
    {
        if let Some((private_key, client_certificate)) = &self.cert_private_key {
            let transcript_hash: Vec<u8, U64> =
                if let Ok(sha256) = self.hash.get_sha256_clone() {
                    Vec::from_slice(&sha256.finalize()).unwrap()
                } else if let Ok(sha384) = self.hash.get_sha384_clone() {
                    Vec::from_slice(&sha384.finalize()).unwrap()
                } else {
                    unreachable!()
                };
            
            use crate::tls_packet::SignatureScheme::*;
            // RSA signature must be with PSS padding scheme
            let mut get_rsa_padding_scheme = |sig_alg: SignatureScheme|
                -> (SignatureScheme, PaddingScheme)
            {
                match sig_alg {
                    rsa_pkcs1_sha256 => {
                        let mut salt_buffer: [u8; 32] = [0; 32];
                        rng.fill_bytes(&mut salt_buffer);
                        let one_time_rng = OneTimeRandom::new(&salt_buffer);
                        (
                            rsa_pss_rsae_sha256,
                            PaddingScheme::new_pss_with_salt::<Sha256, OneTimeRandom<U32>>(one_time_rng, 32)
                        )
                    },
                    rsa_pkcs1_sha384 => {
                        let salt_buffer: [u8; 48] = [0; 48];
                        let one_time_rng = OneTimeRandom::new(&salt_buffer);
                        (
                            rsa_pss_rsae_sha384,
                            PaddingScheme::new_pss_with_salt::<Sha256, OneTimeRandom<U48>>(one_time_rng, 48)
                        )
                    },
                    rsa_pkcs1_sha512 => {
                        let salt_buffer: [u8; 64] = [0; 64];
                        let one_time_rng = OneTimeRandom::new(&salt_buffer);
                        (
                            rsa_pss_rsae_sha512,
                            PaddingScheme::new_pss_with_salt::<Sha256, OneTimeRandom<U64>>(one_time_rng, 64)
                        )
                    },
                    rsa_pss_rsae_sha256 | rsa_pss_pss_sha256 => {
                        let salt_buffer: [u8; 32] = [0; 32];
                        let one_time_rng = OneTimeRandom::new(&salt_buffer);
                        (
                            sig_alg,
                            PaddingScheme::new_pss_with_salt::<Sha256, OneTimeRandom<U32>>(one_time_rng, 32)
                        )
                    },
                    rsa_pss_rsae_sha384 | rsa_pss_pss_sha384 => {
                        let salt_buffer: [u8; 48] = [0; 48];
                        let one_time_rng = OneTimeRandom::new(&salt_buffer);
                        (
                            sig_alg,
                            PaddingScheme::new_pss_with_salt::<Sha256, OneTimeRandom<U48>>(one_time_rng, 48)
                        )
                    },
                    rsa_pss_rsae_sha512 | rsa_pss_pss_sha512 => {
                        let salt_buffer: [u8; 64] = [0; 64];
                        let one_time_rng = OneTimeRandom::new(&salt_buffer);
                        (
                            sig_alg,
                            PaddingScheme::new_pss_with_salt::<Sha256, OneTimeRandom<U64>>(one_time_rng, 64)
                        )
                    },
                    _ => unreachable!()
                }
            };

            match private_key {
                CertificatePrivateKey::RSA { cert_rsa_private_key } => {
                    let sig_alg = self.client_cert_verify_sig_alg.unwrap();
                    let verify_hash: Vec<u8, U64> = match sig_alg {
                        rsa_pkcs1_sha256 | rsa_pss_rsae_sha256 | rsa_pss_pss_sha256 => {
                            Vec::from_slice(
                                &sha2::Sha256::new()
                                    .chain(&[0x20; 64])
                                    .chain("TLS 1.3, client CertificateVerify")
                                    .chain(&[0x00])
                                    .chain(&transcript_hash)
                                    .finalize()
                            ).unwrap()
                        },
                        rsa_pkcs1_sha384 | rsa_pss_rsae_sha384 | rsa_pss_pss_sha384 => {
                            Vec::from_slice(
                                &sha2::Sha384::new()
                                    .chain(&[0x20; 64])
                                    .chain("TLS 1.3, client CertificateVerify")
                                    .chain(&[0x00])
                                    .chain(&transcript_hash)
                                    .finalize()
                            ).unwrap()
                        },
                        rsa_pkcs1_sha512 | rsa_pss_rsae_sha512 | rsa_pss_pss_sha512 => {
                            Vec::from_slice(
                                &sha2::Sha512::new()
                                    .chain(&[0x20; 64])
                                    .chain("TLS 1.3, client CertificateVerify")
                                    .chain(&[0x00])
                                    .chain(&transcript_hash)
                                    .finalize()
                            ).unwrap()
                        },
                        _ => unreachable!()
                    };
                    let (modified_sig_alg, padding) = get_rsa_padding_scheme(sig_alg);
                    (
                        modified_sig_alg,
                        cert_rsa_private_key.sign(
                            padding, &verify_hash
                        ).unwrap()
                    )
                },

                CertificatePrivateKey::ECDSA_SECP256R1_SHA256 { cert_signing_key } => {
                    let verify_hash = sha2::Sha256::new()
                        .chain(&[0x20; 64])
                        .chain("TLS 1.3, client CertificateVerify")
                        .chain(&[0x00])
                        .chain(&transcript_hash);
                    
                    use p256::ecdsa::signature::DigestSigner;
                    let sig_vec = alloc::vec::Vec::from(
                        cert_signing_key.sign_digest(verify_hash).to_asn1().as_ref()
                    );

                    (
                        ecdsa_secp256r1_sha256,
                        sig_vec
                    )
                },

                CertificatePrivateKey::ED25519 { cert_eddsa_key } => {
                    // Similar to server CertificateVerify
                    let mut verify_message: Vec<u8, U146> = Vec::new();
                    verify_message.extend_from_slice(&[0x20; 64]).unwrap();
                    verify_message.extend_from_slice(b"TLS 1.3, client CertificateVerify").unwrap();
                    verify_message.extend_from_slice(&[0]).unwrap();
                    verify_message.extend_from_slice(&transcript_hash).unwrap();
                    
                    // Ed25519 requires a key-pair to sign
                    // Get public key from certificate
                    let certificate = crate::parse::parse_asn1_der_certificate(
                        client_certificate[0]
                    ).unwrap().1;

                    let cert_public_key = certificate
                        .get_cert_public_key()
                        .unwrap();
                    let ed25519_public_key = cert_public_key
                        .get_ed25519_public_key()
                        .unwrap();

                    let mut keypair_bytes: [u8; 64] = [0; 64];
                    &keypair_bytes[..32].clone_from_slice(cert_eddsa_key.as_bytes());
                    &keypair_bytes[32..].clone_from_slice(ed25519_public_key.as_bytes());

                    let ed25519_keypair = ed25519_dalek::Keypair::from_bytes(
                        &keypair_bytes
                    ).unwrap();

                    use ed25519_dalek::Signer;
                    let sig_vec = alloc::vec::Vec::from(
                        ed25519_keypair
                            .sign(&verify_message)
                            .as_ref()
                    );

                    (
                        ed25519,
                        sig_vec
                    )
                }
            }
        }
        else {
            // Should definitely NOT be invoking this function
            // TODO: Throw error
            todo!()
        }

    }

    pub(crate) fn get_client_finished_verify_data(&self) -> Vec<u8, U64> {
        if let Ok(sha256) = self.hash.get_sha256_clone() {
            let hkdf = Hkdf::<Sha256>::from_prk(
                self.client_handshake_traffic_secret.as_ref().unwrap()
            ).unwrap();

            // Compute finished_key
            let mut okm: GenericArray::<u8, <Sha256 as Digest>::OutputSize> = 
                Default::default();
            hkdf_expand_label(&hkdf, "finished", "", &mut okm);

            // Get transcript hash
            let transcript_hash = sha256.finalize();

            // Compute verify_data, store in heapless vec
            let mut hmac = Hmac::<Sha256>::new_varkey(&okm).unwrap();
            hmac.update(&transcript_hash);
            Vec::from_slice(&hmac.finalize().into_bytes()).unwrap()

        } else if let Ok(sha384) = self.hash.get_sha384_clone() {
            let hkdf = Hkdf::<Sha384>::from_prk(
                self.client_handshake_traffic_secret.as_ref().unwrap()
            ).unwrap();

            // Compute finished_key
            let mut okm: GenericArray::<u8, <Sha384 as Digest>::OutputSize> = 
                Default::default();
            hkdf_expand_label(&hkdf, "finished", "", &mut okm);

            // Get transcript hash
            let transcript_hash = sha384.finalize();

            // Compute verify_data, store in heapless vec
            let mut hmac = Hmac::<Sha384>::new_varkey(&okm).unwrap();
            hmac.update(&transcript_hash);
            Vec::from_slice(&hmac.finalize().into_bytes()).unwrap()

        } else {
            unreachable!()
        }
    }

    pub(crate) fn get_cipher_suite_type(&self) -> Option<CipherSuite> {
        self.client_handshake_cipher.as_ref().map(|cipher| cipher.get_cipher_suite_type())
    }

    // TODO: Merge decryption methods
    pub(crate) fn encrypt_application_data_in_place_detached(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8]
    ) -> Result<GenericArray<u8, U16>, Error> {
        let (seq_num, nonce, cipher): (u64, &Vec<u8, U12>, &Cipher) = match self.role {
            TlsRole::Client => {(
                self.client_sequence_number,
                self.client_application_nonce.as_ref().unwrap(),
                self.client_application_cipher.as_ref().unwrap()
            )},
            TlsRole::Server => {(
                self.server_sequence_number,
                self.server_application_nonce.as_ref().unwrap(),
                self.server_application_cipher.as_ref().unwrap()
            )},
            TlsRole::Unknown => unreachable!()
        };

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = seq_num.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        cipher.encrypt_in_place_detached(
            &GenericArray::from_slice(&processed_nonce),
            associated_data,
            buffer
        )
    }

    pub(crate) fn encrypt_in_place(
        &self,
        associated_data: &[u8],
        buffer: &mut dyn Buffer
    ) -> Result<(), Error> {
        let (seq_num, nonce, cipher): (u64, &Vec<u8, U12>, &Cipher) = match self.role {
            TlsRole::Client => {(
                self.client_sequence_number,
                self.client_handshake_nonce.as_ref().unwrap(),
                self.client_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Server => {(
                self.server_sequence_number,
                self.server_handshake_nonce.as_ref().unwrap(),
                self.server_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Unknown => unreachable!()
        };

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = seq_num.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        cipher.encrypt_in_place(
            &GenericArray::from_slice(&processed_nonce),
            associated_data,
            buffer
        )
    }

    pub(crate) fn encrypt_in_place_detached(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8]
    ) -> Result<GenericArray<u8, U16>, Error> {
        let (seq_num, nonce, cipher): (u64, &Vec<u8, U12>, &Cipher) = match self.role {
            TlsRole::Client => {(
                self.client_sequence_number,
                self.client_handshake_nonce.as_ref().unwrap(),
                self.client_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Server => {(
                self.server_sequence_number,
                self.server_handshake_nonce.as_ref().unwrap(),
                self.server_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Unknown => unreachable!()
        };

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = seq_num.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        cipher.encrypt_in_place_detached(
            &GenericArray::from_slice(&processed_nonce),
            associated_data,
            buffer
        )
    }

    // TODO: Merge decryption methods
    // Take control of the entire decryption, manually invoke detached decryption
    // TODO: Bad naming, it should say the KEY of application data
    pub(crate) fn decrypt_application_data_in_place(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        let (seq_num, nonce, cipher): (u64, &Vec<u8, U12>, &Cipher) = match self.role {
            TlsRole::Client => {(
                self.server_sequence_number,
                self.server_application_nonce.as_ref().unwrap(),
                self.server_application_cipher.as_ref().unwrap()
            )},
            TlsRole::Server => {(
                self.client_sequence_number,
                self.client_application_nonce.as_ref().unwrap(),
                self.client_application_cipher.as_ref().unwrap()
            )},
            TlsRole::Unknown => unreachable!()
        };

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = seq_num.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        // Duplicate authentication tag
        let buffer_size = buffer.len();
        let tag = GenericArray::clone_from_slice(&buffer[(buffer_size-16)..]);

        cipher.decrypt_in_place_detached(
            &GenericArray::from_slice(&processed_nonce),
            associated_data,
            &mut buffer[..(buffer_size-16)],
            &tag
        )
    }

    // Decryption using handshake keys
    pub(crate) fn decrypt_in_place(
        &self,
        associated_data: &[u8],
        buffer: &mut dyn Buffer
    ) -> Result<(), Error> {
        let (seq_num, nonce, cipher): (u64, &Vec<u8, U12>, &Cipher) = match self.role {
            TlsRole::Server => {(
                self.client_sequence_number,
                self.client_handshake_nonce.as_ref().unwrap(),
                self.client_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Client => {(
                self.server_sequence_number,
                self.server_handshake_nonce.as_ref().unwrap(),
                self.server_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Unknown => unreachable!()
        };

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = seq_num.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        cipher.decrypt_in_place(
            &GenericArray::from_slice(&processed_nonce),
            associated_data,
            buffer
        )
    }

    // A veriant for handshake decryption in-place and detached
    // Caller need to manually discard the authentication bytes
    pub(crate) fn decrypt_in_place_detached(
        &self,
        associated_data: &[u8],
        buffer: &mut [u8]
    ) -> Result<(), Error> {

        let (seq_num, nonce, cipher): (u64, &Vec<u8, U12>, &Cipher) = match self.role {
            TlsRole::Server => {(
                self.client_sequence_number,
                self.client_handshake_nonce.as_ref().unwrap(),
                self.client_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Client => {(
                self.server_sequence_number,
                self.server_handshake_nonce.as_ref().unwrap(),
                self.server_handshake_cipher.as_ref().unwrap()
            )},
            TlsRole::Unknown => unreachable!()
        };

        // Calculate XOR'ed nonce
        let nonce: u128 = NetworkEndian::read_uint128(nonce, 12);
        let clipped_seq_num: u128 = seq_num.into();
        let mut processed_nonce: [u8; 12] = [0; 12];
        NetworkEndian::write_uint128(&mut processed_nonce, nonce ^ clipped_seq_num, 12);

        // Duplicate authentication tag
        let buffer_size = buffer.len();
        let tag = GenericArray::clone_from_slice(&buffer[(buffer_size-16)..]);

        cipher.decrypt_in_place_detached(
            &GenericArray::from_slice(&processed_nonce),
            associated_data,
            &mut buffer[..(buffer_size-16)],
            &tag
        )
    }

    pub(crate) fn increment_client_sequence_number(&mut self) {
        self.client_sequence_number += 1;
    }

    pub(crate) fn increment_server_sequence_number(&mut self) {
        self.server_sequence_number += 1;
    }

    pub(crate) fn get_session_role(&self) -> TlsRole {
        self.role
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum TlsRole {
    Client,
    Server,
    Unknown,
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
            Self::Undetermined { sha256, .. } => {
                Self::Sha256 {
                    sha256
                }
            },
            _ => unreachable!()
        }
    }

    pub(crate) fn select_sha384(self) -> Self {
        match self {
            Self::Undetermined { sha384, .. } => {
                Self::Sha384 {
                    sha384
                }
            },
            _ => unreachable!()
        }
    }

    pub(crate) fn get_sha256_clone(&self) -> Result<Sha256, ()> {
        if let Self::Sha256 { sha256 } = self {
            Ok(sha256.clone())
        } else {
            Err(())
        }
    }

    pub(crate) fn get_sha384_clone(&self) -> Result<Sha384, ()> {
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

    pub(crate) fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, U12>,
        associated_data: &[u8],
        buffer: &mut [u8]
    ) -> Result<GenericArray<u8, U16>, Error> {
        match self {
            Cipher::Aes128Gcm { aes128gcm } => {
                aes128gcm.encrypt_in_place_detached(nonce, associated_data, buffer)
            },
            Cipher::Aes256Gcm { aes256gcm } => {
                aes256gcm.encrypt_in_place_detached(nonce, associated_data, buffer)
            },
            Cipher::Chacha20poly1305 { chacha20poly1305 } => {
                chacha20poly1305.encrypt_in_place_detached(nonce, associated_data, buffer)
            },
            Cipher::Ccm { ccm } => {
                ccm.encrypt_in_place_detached(nonce, associated_data, buffer)
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

    pub(crate) fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, U12>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, U16>
    ) -> Result<(), Error> {
        match self {
            Cipher::Aes128Gcm { aes128gcm } => {
                aes128gcm.decrypt_in_place_detached(
                    nonce, associated_data, buffer, tag
                )
            },
            Cipher::Aes256Gcm { aes256gcm } => {
                aes256gcm.decrypt_in_place_detached(
                    nonce, associated_data, buffer, tag
                )
            },
            Cipher::Chacha20poly1305 { chacha20poly1305 } => {
                chacha20poly1305.decrypt_in_place_detached(
                    nonce, associated_data, buffer, tag
                )
            },
            Cipher::Ccm { ccm } => {
                ccm.decrypt_in_place_detached(
                    nonce, associated_data, buffer, tag
                )
            }
        }.map_err(|_| Error::DecryptionError)
    }

    pub(crate) fn get_cipher_suite_type(&self) -> CipherSuite {
        match self {
            Cipher::Aes128Gcm { .. } => {
                CipherSuite::TLS_AES_128_GCM_SHA256
            },
            Cipher::Aes256Gcm { .. } => {
                CipherSuite::TLS_AES_256_GCM_SHA384
            },
            Cipher::Chacha20poly1305 { .. } => {
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256
            },
            Cipher::Ccm { .. } => {
                CipherSuite::TLS_AES_128_CCM_SHA256
            }
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone)]
pub enum CertificatePublicKey {
    RSA {
        cert_rsa_public_key: RSAPublicKey
    },
    ECDSA_SECP256R1_SHA256 {
        cert_verify_key: p256::ecdsa::VerifyKey
    },
    ED25519 {
        cert_eddsa_key: ed25519_dalek::PublicKey
    }
}

impl CertificatePublicKey {
    pub(crate) fn get_rsa_public_key(&self) -> Result<&RSAPublicKey, ()> {
        if let CertificatePublicKey::RSA { cert_rsa_public_key } = self {
            Ok(&cert_rsa_public_key)
        } else {
            Err(())
        }
    }
    pub(crate) fn get_ecdsa_secp256r1_sha256_verify_key(&self) -> Result<&p256::ecdsa::VerifyKey, ()> {
        if let CertificatePublicKey::ECDSA_SECP256R1_SHA256 {
            cert_verify_key
        } = self {
            Ok(&cert_verify_key)
        } else {
            Err(())
        }
    }
    pub(crate) fn get_ed25519_public_key(&self) -> Result<&ed25519_dalek::PublicKey, ()> {
        if let CertificatePublicKey::ED25519 { cert_eddsa_key } = self {
            Ok(&cert_eddsa_key)
        } else {
            Err(())
        }
    }
}

#[allow(non_camel_case_types)]
pub enum CertificatePrivateKey {
    RSA {
        cert_rsa_private_key: rsa::RSAPrivateKey
    },
    ECDSA_SECP256R1_SHA256 {
        cert_signing_key: p256::ecdsa::SigningKey
    },
    ED25519 {
        cert_eddsa_key: ed25519_dalek::SecretKey
    }
}
