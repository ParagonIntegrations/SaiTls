use smoltcp_tls::tls::TlsSocket;
use smoltcp::socket::TcpSocketBuffer;
use smoltcp::socket::SocketSet;
use smoltcp::wire::Ipv4Address;

use rand_core::RngCore;
use rand_core::CryptoRng;
use rand_core::impls;
use rand_core::Error;

use p256::{EncodedPoint, AffinePoint, ecdh::EphemeralSecret, ecdh::SharedSecret};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use ccm::{Ccm, consts::*};
use aes_gcm::aes::Aes128;
use aes_gcm::{AeadInPlace, NewAead};
use generic_array::GenericArray;
use sha2::{ Digest, Sha256, Sha384, Sha512 };
use std::vec::Vec;
use hkdf::Hkdf;

use rand::rngs::OsRng;

use chrono::prelude::*;

use smoltcp_tls::key::*;
use smoltcp_tls::buffer::TlsBuffer;
use smoltcp_tls::certificate::*;
use smoltcp_tls::parse::*;

struct CountingRng(u64);

impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.fill_bytes(dest))
    }
}

impl CryptoRng for CountingRng {}

static mut RNG: CountingRng = CountingRng(0);

fn main() {
    let mut socket_set_entries: [_; 8] = Default::default();
    let mut sockets = SocketSet::new(&mut socket_set_entries[..]);

    let mut tx_storage = [0; 4096];
    let mut rx_storage = [0; 4096];

    let mut tls_socket = unsafe {
        let tx_buffer = TcpSocketBuffer::new(&mut tx_storage[..]);
        let rx_buffer = TcpSocketBuffer::new(&mut rx_storage[..]);
        TlsSocket::new(
            &mut sockets,
            rx_buffer,
            tx_buffer,
            &mut RNG,
            None
        )
    };

    tls_socket.tcp_connect(
        &mut sockets,
        (Ipv4Address::new(192, 168, 1, 125), 1883),
        49600
    ).unwrap();

//    tls_socket.tls_connect(&mut sockets).unwrap();
    simple_logger::SimpleLogger::new().init().unwrap();

    let (_, certificate) = parse_asn1_der_certificate(&RSA_PSS_SELF_CERT).unwrap();
    // println!("Certificate print: {:?}", certificate);

    // let modulus = [
    //     0x00, 0xe1, 0x64, 0x42, 0x1f, 0x32, 0x2c, 0xa2, 0x81, 0x3a, 0x6f, 0x9d, 0x4e, 0x6d, 0xa7, 0xc9, 0xed, 0xb9, 0x47, 0x3e, 0xd8, 0x98, 0xe6, 0xba, 0xab, 0x07, 0x93, 0xb3, 0xc5, 0x80, 0x62, 0x7e, 0xb7, 0xe3, 0x9a, 0xfb, 0x9c, 0xf4, 0x0c, 0xc7, 0x49, 0x08, 0x73, 0x45, 0xe8, 0x94, 0xff, 0xb1, 0xe7, 0x52, 0xb6, 0x77, 0xa7, 0x53, 0x49, 0x0b, 0xf3, 0xe6, 0x13, 0x4a, 0x79, 0xd7, 0xef, 0x53, 0x7c, 0x8d, 0x84, 0x5b, 0xf3, 0x30, 0x6d, 0x4d, 0x43, 0x14, 0xa0, 0xc9, 0x8b, 0x86, 0x17, 0x16, 0x8a, 0x09, 0x60, 0xa9, 0xdb, 0x76, 0x8f, 0x5c, 0x58, 0x92, 0xf3, 0x63, 0xdb, 0x39, 0x82, 0xa7, 0x4a, 0x79, 0x08, 0x29, 0x1d, 0x94, 0x3c, 0xec, 0x11, 0x46, 0x70, 0xf8, 0xd1, 0xe4, 0xc2, 0x6f, 0x9d, 0x40, 0x8d, 0x8a, 0x29, 0x2e, 0x2b, 0x82, 0xd6, 0x1b, 0x0f, 0xbd, 0x49, 0xe4, 0xc9, 0xfb, 0xc3, 0x81, 0x29, 0x7f, 0x99, 0x07, 0x99, 0x5a, 0x28, 0x46, 0xf7, 0xdd, 0xca, 0xb2, 0x4c, 0xce, 0x21, 0x01, 0x24, 0xfc, 0xfe, 0x8f, 0xea, 0x73, 0x36, 0x39, 0xdf, 0xa0, 0x6c, 0x43, 0xf5, 0x3c, 0x74, 0xb3, 0x17, 0x00, 0xfd, 0xb4, 0xa2, 0x82, 0x1e, 0xed, 0xdf, 0x22, 0x2a, 0x35, 0x6d, 0xf7, 0x8a, 0x4d, 0xc8, 0x19, 0xb9, 0xd3, 0x88, 0x29, 0x10, 0x8e, 0xae, 0x30, 0xf2, 0x23, 0xce, 0x3b, 0xce, 0xe0, 0x7c, 0x5e, 0x52, 0xa1, 0x1f, 0xc1, 0x59, 0xcc, 0x14, 0xf6, 0x6f, 0xf1, 0xa6, 0xbb, 0xfd, 0x9b, 0x66, 0x96, 0x89, 0xbb, 0xd4, 0x0b, 0x9e, 0x5f, 0xac, 0xf0, 0x1d, 0x88, 0xa6, 0x27, 0x53, 0x48, 0xf2, 0x12, 0x54, 0x43, 0xf8, 0x92, 0x42, 0xcd, 0x6e, 0x00, 0x54, 0x67, 0x55, 0x6f, 0xfa, 0x38, 0x30, 0x7b, 0xea, 0xaa, 0x85, 0x9b, 0x31, 0xbf, 0x78, 0xb8, 0x2a, 0x97, 0x77, 0xd0, 0x23
    // ];

    // let exponent = [1, 0, 1];

    // let rsa_public_key = rsa::RSAPublicKey::new(
    //     rsa::BigUint::from_bytes_be(&modulus),
    //     rsa::BigUint::from_bytes_be(&exponent)
    // ).unwrap();

    // let ca_public_key = smoltcp_tls::session::CertificatePublicKey::RSA {
    //     cert_rsa_public_key: rsa_public_key
    // };
    // certificate.validate_signature_with_trusted(&ca_public_key).unwrap();
    // println!("Certificate should be trusted");

    certificate.validate_self_signed_signature().unwrap();
    println!("Certificate should be trusted");
/*


    
    let mut certificate_vec = Vec::new();
    let name = parse_asn1_der_name(&SELF_SIGNED_WITH_SAN_ISSUER).unwrap().1;
    let public_key = certificate.get_cert_public_key().unwrap();
    let mut permitted_name: Vec<GeneralName> = Vec::new();
    let mut excluded_name: Vec<GeneralName> = Vec::new();

    // let mut stricter_name = name.clone();
    // let att = AttributeTypeAndValue {
    //     attribute_type: &[1, 2, 3, 4, 5],
    //     attribute_value: "additional value"
    // };
    // let mut rdn = RelativeDistinguishedName {
    //     type_and_attributes: Vec::new()
    // };
    // rdn.type_and_attributes.push(att);
    // stricter_name.relative_distinguished_name.push(rdn);
    // log::info!("Stricter name: {:?}", stricter_name);
    // let directory_general_name = GeneralName::DirectoryName(stricter_name.clone());

    // let mut broader_name = name.clone();
    // broader_name.relative_distinguished_name.remove(0);
    // log::info!("Broader name: {:?}", broader_name);
    // let directory_general_name = GeneralName::DirectoryName(broader_name.clone());

    let mut empty_name = Name {
        relative_distinguished_name: Vec::new()
    };
    log::info!("Empty name: {:?}", empty_name);
    let directory_general_name = GeneralName::DirectoryName(empty_name.clone());

    permitted_name.push(directory_general_name.clone());
    // excluded_name.push(directory_general_name);
    
    certificate_vec.push(certificate);

    verify_certificate_chain(
        certificate_vec,
        DateTime::<FixedOffset>::from(Utc::now()),
        name,
        public_key,
        false,
        false,
        false,
        permitted_name,
        excluded_name
    ).unwrap();
*/
    let google_end_entity_certificate = parse_asn1_der_certificate(
        &GOOGLE_END_ENTITY_CERT
    ).unwrap().1;

    let google_root_ca_certificate = parse_asn1_der_certificate(
        &GOOGLE_ROOT_CERT
    ).unwrap().1;

    google_end_entity_certificate.validate_signature_with_trusted(
        &google_root_ca_certificate.get_cert_public_key().unwrap()
    ).unwrap();
    log::info!("End entity certificate verified");

    // google_root_ca_certificate.validate_self_signed_signature().unwrap();
    // log::info!("root certificate verified");

//     let mut certificate_vec: Vec<Certificate> = Vec::new();
//     certificate_vec.push(google_root_ca_certificate);
//     certificate_vec.push(google_end_entity_certificate);

//     let mut certificate_vec = Vec::new();
//     let name = google_root_ca_certificate.tbs_certificate.issuer;
//     let public_key = google_root_ca_certificate.get_cert_public_key().unwrap();
//     let mut permitted_name: Vec<GeneralName> = Vec::new();
//     let mut excluded_name: Vec<GeneralName> = Vec::new();
    
//     verify_certificate_chain(
//         certificate_vec,
//         DateTime::<FixedOffset>::from(Utc::now()),
//         name,
//         public_key,
//         false,
//         false,
//         false,
//         permitted_name,
//         excluded_name
//     ).unwrap();

    use rand_core::{RngCore, OsRng};
    use rsa::PublicKey;
    use rsa::BigUint;
    use smoltcp_tls::fake_rng::FakeRandom;

    let mut prime_vec = std::vec::Vec::new();
    prime_vec.extend_from_slice(&[
        BigUint::from_bytes_be(&CLIENT_PRIME_1),
        BigUint::from_bytes_be(&CLIENT_PRIME_2)
    ]);
    let rsa_client_private_key = rsa::RSAPrivateKey::from_components(
        BigUint::from_bytes_be(&CLIENT_PRIVATE_KEY_MOD),
        BigUint::from_bytes_be(&CLIENT_PRIVATE_KEY_EXP),
        BigUint::from_bytes_be(&CLIENT_PRIVATE_KEY_PMOD),
        prime_vec
    );
    let public_key_from_conversion = rsa_client_private_key.to_public_key();
    let rsa_client_public_key = 
        rsa::RSAPublicKey::from_pkcs1(&CLIENT_PUBLIC_KEY).unwrap();

    println!("Public key from conversion: {:?}", public_key_from_conversion);
    println!("Public key from certificate: {:?}", rsa_client_public_key);
    println!("Public key are the same: {:?}",
        public_key_from_conversion == rsa_client_public_key);
    
    let checked_hash = sha2::Sha256::new()
        .chain(&[0x20; 64])
        .chain("TLS 1.3, client CertificateVerify")
        .chain(&[0])
        .chain(&CLIENT_TRANSCRIPT_HASH)
        .finalize();
    
    let padding = rsa::PaddingScheme::new_pss_with_salt::<sha2::Sha256, OsRng>(OsRng, 32);
    let sign = rsa_client_private_key.sign(padding, &checked_hash).unwrap();

    println!("Signature with salt: {:X?}", sign);

    let padding = rsa::PaddingScheme::new_pss_with_salt::<sha2::Sha256, OsRng>(OsRng, 222);
    rsa_client_public_key.verify(padding, &checked_hash, &sign).unwrap();

    println!("Signature verified");
}

const RSA_PSS_CERT: [u8; 0x3AB] =
    hex_literal::hex!("308203a73082028fa00302010202146642be8f709457f9cd6eed72051c240a5565138c300d06092a864886f70d01010a30003063310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311c301a06035504030c136578616d706c652e756c666865696d2e6e6574301e170d3230313130343039313535325a170d3231313130343039313535325a3063310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311c301a06035504030c136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100b5a347b654ca0bad8d56990e70aa7411b78dedc9fd9a6760ee936ea01486238538dbc4d0bc95a1a5f060b6296ba67001f103cfd918ad1ec33a1a680d4e8283a24300391e9a53cd6641fc51f0a984c3cd16542b934a0ec8c3447782542628320d6c24988cf0b7b19bbaba91f1999968def724d8e65b624fbb9826208aece1ee90badda7c6b8a97fc4085299f9d32661a06bc67d2d662e0efcee1df5b6dc1d02e56929d8976441456d0fe50314c9861e9845f75f5dc2ca9828089b5d4bd109d1e8ada8986c5bd68ee004a7bfcb932768023e11fe8e299b25b8774ed8bdbb0f644ddaa83df1ff4e84bfc18d3b815decb5ca4f1db1125df98dba94e4ef5570ec5a510203010001a3533051301d0603551d0e04160414050928eff30f3094f01ddb09f1d7a9193addf854301f0603551d23041830168014050928eff30f3094f01ddb09f1d7a9193addf854300f0603551d130101ff040530030101ff300d06092a864886f70d01010a300003820101002d14281587dc33d4559e77852d17fade1a9f3f0e5af847bde80c921be360d6e3b598dfb50aad706de3832841798b66736b9296a83c06e0078dceabc39760a5bf5eb7a7287859b22e9beb7ebb928b99034d155fd12307ee541ea53979bb8afb62db233dfcf1e16afea5eac33817b8cbb13841cb89e9b65a5a4b08a6c6e3d1e0036bc9576b90cf62437e3ef985f02b88be4e6863068c9bc45dd473763f4cdcfc3bfb8a90d7b3225b67a3a39c6ac446de55596dc135221b4383773ddd9efdcca48f389af9c1c0547e0ada1c14153fc38e02c95e4c37da45af1e6d3b0a6cafb603d95a1c887384b476caf60783835a150ee7fd22b6838ce19adcb2e59572c6349703");

const RSA_PSS_SELF_CERT: [u8; 0x405] =
    hex_literal::hex!(
        "30820401308202b8a0030201020214298b26a4c6033fbde6cae4add099ebad73837d57303e06092a864886f70d01010a3031a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a204020200de3060310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706035504030c106e6f775f776974685f7368615f323536301e170d3230313131363039343634395a170d3230313231363039343634395a3060310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706035504030c106e6f775f776974685f7368615f32353630820120300b06092a864886f70d01010a0382010f003082010a0282010100c9f77901168ee11c6f3a62143a7d6c693012e34e76910c64292ea38049e5f60b7aa9aa3d17cf28d91e2449864a42b45db2283412d714ecb50200723dda269fac3a36841f2627cf4c808676c87dd116a361bbdfcacaa6bd74f27a67e2f8d1532646ecec9ddb5a0a3fb490cf440c1f9381cb764d1fdfe9d7ce1aab606e1f30267771e21af1d6b9c11c39e21c9628789d1812d6d776abe80dcc4f11ce51facafd8dbde0d8beccf10ce1309f160ec49f1e42a2b1c26e8567a8db62af1d267ec84341c0851b121ec158f0ba383b46128b23d4397c5393a3032c50036197da8b7673e38a755ce41744322b0bffb228fe3084f0fa6177741d59613dfad61c8f419f32cb0203010001a3533051301d0603551d0e04160414ee19f554ae1d1cb9d5a316a997412168a23f1408301f0603551d23041830168014ee19f554ae1d1cb9d5a316a997412168a23f1408300f0603551d130101ff040530030101ff303e06092a864886f70d01010a3031a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a204020200de0382010100bebe84986a245ed68b35acb1b9683bea68d43481f02e2eabe5c2a5091ee16896dbc8a0d3c27602e1136ec81ba3be5fcd2d565001085c399ae166c74fc798ae61201df4a6e5a308b8b0ab4ac3dce5e6668a10843a477ec5c6555cca2dd0520b0151cf942cc3293c31e0242bf6d3a19c33df9a29fab1a151542949e126243f468cb4268200fd61a9b5f0be128adf8616ca284180cbc8c4db09607fd03e1dc687ce2dd843b63cb02133f3c22c1f4c0024ff89352611dda6efba9c7b5ad4fefcb76a3aea75c922f3a1bcc669656b920878339827bbf09bca982f878fe4a72a63316b8fedd8a5654e5f1d876cc6083d64d8ea1c12e182ee200f9766734f212e460d56"
    );

const RSA_PKCS_CERT: [u8; 0x03AB] =
    hex_literal::hex!("308203a73082028fa00302010202144a5a52142c495ec189e661457ba0330809c9dede300d06092a864886f70d01010b05003063310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311c301a06035504030c13746573742e68656c6c6f776f726c642e636f6d301e170d3230313130343038353031325a170d3231313130343038353031325a3063310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311c301a06035504030c13746573742e68656c6c6f776f726c642e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100a665127e115e41937b51f87fa44d9894e52a45479a234110037f8c8ce2de6d263e12e3824d57a39d7386afe35cb926af1d6f593673eae31f1e27b8914895006fc7e5fdac11f369b73741a97663f2bb08edb7ab7c1ccc8be9259ce2c1b9d04ba066e05fd6a440ca99b148ddc95a23432228f5172b32939921f70f4f632691ee19a50d7deffb50cb9f018562c803065ca1f1817f1f93c25b3aa0ef91b2f91ef1c86fd346bc00ac165fbd5abf04d944a58e48fd24959133637a949cb85d498063aa4ed0927327591d125500430fa91782af806d46fe330251103c8139b3bf35034b009748324a0fffac2474eed6f04e8d90582dc6125cce0274305f28e82b5409170203010001a3533051301d0603551d0e04160414a36633b9660897096d8138d4f0281a3b76e6696c301f0603551d23041830168014a36633b9660897096d8138d4f0281a3b76e6696c300f0603551d130101ff040530030101ff300d06092a864886f70d01010b0500038201010090631de179bf4940e636e0e7142d9feb440d818c9ea095b6ae31a4ad9876fbd1c2b6808d2edc60e20b107daaf592d14bb9f1ca37c9d975b0c463478dbac8cb183b90bbaecdb1ad5541674f3ba957f2837e57480c445328f917c8a358fc5465c1f838108f60b59327cd1fba59e1635276372bdb17557b636b59be60b4c6b6cf3ecb9fd40b9469d7bfa4f2053be4c08e2e350453050a076d923923588c7f839c709d31c2296dfd837b850f0ba4b44a36c112b9a6ef7186b090162628367a95fa1673e4362d7a23aebd46a85c69eac76f7194d166c89ce6103c508eb970f35bf0b241cbbae5ddffc5ea6515e5f36a8645dc0c8a48798199f65f01b811bec2f287d5");

const ECDSA_P256_CERT: [u8; 0x0219] =
    hex_literal::hex!("30820215308201bba003020102021441d0428ae91b87ccb66e64cf3bdbd96ef0871630300a06082a8648ce3d0403023060310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706092a864886f70d010901160a68656c6c6f776f726c64301e170d3230313130353033313932325a170d3330313130333033313932325a3060310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643119301706092a864886f70d010901160a68656c6c6f776f726c643059301306072a8648ce3d020106082a8648ce3d03010703420004d22bf2abba402fa10f6d97f941465d5966a965cc8f288bb7920e8c9e8c50607ef3a0a183916913ed9f4dfb42452fe972a2a5ac7a2f4443ef2a0012a481957d10a3533051301d0603551d0e041604147383be1d07af30366a8c3c377d048759f802e885301f0603551d230418301680147383be1d07af30366a8c3c377d048759f802e885300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100c048d13d28a811a67262d1593ea0f4af51812751632d391b7d85666fcd5e591702202b1a2db620b764ff61a7be0808069518c75d1bed60c1e9c98debfa98d7a23134");

const ED25519_CERT: [u8; 0x0187] =
    hex_literal::hex!("30820183308201350214644c27b38f4bd515d9c06f72609ed50844499917300506032b65703064310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311d301b06035504030c146578616d706c65732e756c666865696d2e6e6574301e170d3230313130353035313435365a170d3232313030363035313435365a3064310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311d301b06035504030c146578616d706c65732e756c666865696d2e6e6574302a300506032b6570032100be9d2a3f45d7bd86a6fba8acf3dc58d1241e4272f100c81779bc43e96b779515300506032b6570034100b7017b76d0f9f6f58f7bb28de5459c127a3a539ed73997dcd42a0e0484d5768d42b5f5b0e275c99b856124b20983b2dca66dec380b15b5425f9ccf87a3dc5700");

const CA_SIGNED_CERT: [u8; 0x0356] =
    hex_literal::hex!(
        "308203523082023a02146048517ee55aabd1e8f2bd7db1d91e679708e644300d06092a864886f70d01010b05003067310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643120301e06035504030c176578616d706c65732e63612e756c666865696d2e6e6574301e170d3230313130363034323035305a170d3230313230363034323035305a3064310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311d301b06035504030c146578616d706c65732e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100b2940671bfe7ace7416ba9d34018c229588e9d4eed8bd6623e44ab1239e8f1f0de9050b2f485a98e63f5b483330fb0b5abaeb33d11889033b0b684bf34696d28206bb361782c4b106a8d47874cbbdf971b5ab887bca508bccf250a1a811cee078464638e441941347d4c8885ac9b59d9fc9636276912b04d9e3ab29bd8ad319572ae54f0b6145c4d675a78607dcc4793a4d432f1c2a41ea29dd4f7262b6fe472dfaea51aca992b4624e73fa9901fa364fc5b721052ef3187e659d58d2706770d365380a7ebab6caac5b23271c01531fdf95368ee48af5383035f249be7c18f50ce9e52877558efe4b2e29f61328396e2a3b5e71309ad13d93d6ba3d5c3eb2b650203010001300d06092a864886f70d01010b0500038201010063c9ab0f5d2e164513e8e74b656ae4f48dd004c3ead9f1026b7741cbf02bb0efcf19e0fbf8a788dae059a2393167f016bafc0e3efd5c5b4c43079b6506eb67f17f44f9591503c7d1fdb77bf631894817393ea82610ad5106d23ec6bf1a6d96d749f05c0136cd71256617a51fe862529aee4a37d5f456dc7da8b220ff10ede4e87bc63e4589b3f81133a7f82ab900419e8a2d802d59e99cfbbd268702efd17616168b45b5211da0e644c29dcb92dbbf32b43586bbab05deb0261771605c52836363bd28ff9853d44436349f5ba11f2640bc9c42688e0d5eb6cac9f3f5e5f98652fa4f4ba52604371ec45f09d678e31d463285a4b3734f587f35a339920544f476"
    );

const SELF_SIGNED_WITH_SAN: [u8; 0x048A] =
    hex_literal::hex!(
        "308204863082036ea003020102021447e58ecab88d894c58ec746381e6d039c04e3a93300d06092a864886f70d01010b05003073310b3009060355040613025553310b300906035504080c0256413114301206035504070c0b416e6f746865724369747931123010060355040a0c094d79436f6d70616e7931133011060355040b0c0a4d794469766973696f6e3118301606035504030c0f7777772e636f6d70616e792e636f6d301e170d3230313131303032313132385a170d3231313131303032313132385a3073310b3009060355040613025553310b300906035504080c0256413114301206035504070c0b416e6f746865724369747931123010060355040a0c094d79436f6d70616e7931133011060355040b0c0a4d794469766973696f6e3118301606035504030c0f7777772e636f6d70616e792e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100bacdd00cf364e116a6b7cd23df3ccc31f6d6d2e6e82da833d50f7bd850b1e482acd1e9ecc9e0ea2c36925576fff44bdefbbb73f38c8d7db67ac7210801e5580329504ebc6982e5c95a758a36a1d0ff891478ab2f7392c1c6b4657d08645ff97ef23b0870de511d3532599eb250eac82bae22d6de23f2a5a48733d3a045fe0c5f942b5f79dbb08117bf1a814f00489e4118f30f8e37e66c61c5c4398cdc9f77ec39de78bf0b4c677cb9e485b868ce03c32c41f78849b82949df8231290172618234de85ec02990206fec3ed74b6b18e9d0acd6b4bed1c4f52749574f7cd9b8ad0db14be78a99eb8a894adecdbd0922ab953e3e447346022a4485ffd121efdfe1d0203010001a38201103082010c300b0603551d0f04040302043030130603551d25040c300a06082b0601050507030130760603551d11046f306d820f7777772e636f6d70616e792e6e6574820b636f6d70616e792e636f6d820b636f6d70616e792e6e6574810b626f6240636f6d70616e79810d616c69636540636f6d70616e79a01e06032a0304a0170c15736f6d65206f74686572206964656e7469666965728704c0a801c830430603551d1e043c303aa01c300e820c2e6578616d706c652e636f6d300a8708c0a80001ffffff00a11a300a8708c0aa0001ffffff00300c820a2e6c6f63616c686f7374300f0603551d2404083006800103810105301a0603551d200413301130060604551d2000300706052b05071314300d06092a864886f70d01010b050003820101008e6891f7bf506cb9bbc2d8f679d2d510b0b3121ee4662cbe90ddd1b1fa4f8a5b9cca49877fc64b9c08a2dbbb4563e3e92be62ce79088b2a1b382724f1b479efaba1749696461893335f56e9ad7b89359997af85a20425250be0559b2daf1179b61b65284f39da4386377a035038af179b93508925c227d4f205538c1dedfc768a98cd243196a9476ac79bb91c16e827ff84376520e89b09a236037be4f21b0262b151d156638ccfafac7cf383c5f20213cdd29d0f95329a4a2783328986fa2e70b501289c263e0bdc42cb439412b8be2601b6f1fe8c3e15f11230760d36ff008ccb42d8b10c5c92db35ae2a6a8dfcf461233cefbc30fc2d709608452744f1ce7"
    );

const SELF_SIGNED_WITH_SAN_ISSUER: [u8; 0x75] =
    hex_literal::hex!(
        "3073310b3009060355040613025553310b300906035504080c0256413114301206035504070c0b416e6f746865724369747931123010060355040a0c094d79436f6d70616e7931133011060355040b0c0a4d794469766973696f6e3118301606035504030c0f7777772e636f6d70616e792e636f6d"
    );

const GOOGLE_ROOT_CERT: [u8; 0x044e] =
    hex_literal::hex!(
        "3082044a30820332a003020102020d01e3b49aa18d8aa981256950b8300d06092a864886f70d01010b0500304c3120301e060355040b1317476c6f62616c5369676e20526f6f74204341202d20523231133011060355040a130a476c6f62616c5369676e311330110603550403130a476c6f62616c5369676e301e170d3137303631353030303034325a170d3231313231353030303034325a3042310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573311330110603550403130a47545320434120314f3130820122300d06092a864886f70d01010105000382010f003082010a0282010100d018cf45d48bcdd39ce440ef7eb4dd69211bc9cf3c8e4c75b90f3119843d9e3c29ef500d10936f0580809f2aa0bd124b02e13d9f581624fe309f0b747755931d4bf74de1928210f651ac0cc3b222940f346b981049e70b9d8339dd20c61c2defd1186165e7238320a82312ffd2247fd42fe7446a5b4dd75066b0af9e426305fbe01cc46361af9f6a33ff6297bd48d9d37c1467dc75dc2e69e8f86d7869d0b71005b8f131c23b24fd1a3374f823e0ec6b198a16c6e3cda4cd0bdbb3a4596038883bad1db9c68ca7531bfcbcd9a4abbcdd3c61d7931598ee81bd8fe264472040064ed7ac97e8b9c05912a1492523e4ed70342ca5b4637cf9a33d83d1cd6d24ac070203010001a38201333082012f300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030106082b0601050507030230120603551d130101ff040830060101ff020100301d0603551d0e0416041498d1f86e10ebcf9bec609f18901ba0eb7d09fd2b301f0603551d230418301680149be20757671c1ec06a06de59b49a2ddfdc19862e303506082b0601050507010104293027302506082b060105050730018619687474703a2f2f6f6373702e706b692e676f6f672f6773723230320603551d1f042b30293027a025a0238621687474703a2f2f63726c2e706b692e676f6f672f677372322f677372322e63726c303f0603551d20043830363034060667810c010202302a302806082b06010505070201161c68747470733a2f2f706b692e676f6f672f7265706f7369746f72792f300d06092a864886f70d01010b050003820101001a803e3679fbf32ea946377d5e541635aec74e0899febdd13469265266073d0aba49cb62f4f11a8efc114f68964c742bd367deb2a3aa058d844d4c20650fa596da0d16f86c3bdb6f0423886b3a6cc160bd689f718eee2d583407f0d554e98659fd7b5e0d2194f58cc9a8f8d8f2adcc0f1af39aa7a90427f9a3c9b0ff02786b61bac7352be856fa4fc31c0cedb63cb44beaedcce13cecdc0d8cd63e9bca42588bcc16211740bca2d666efdac4155bcd89aa9b0926e732d20d6e6720025b10b090099c0c1f9eadd83beaa1fc6ce8105c085219512a71bbac7ab5dd15ed2bc9082a2c8ab4a621ab63ffd7524950d089b7adf2affb50ae2fe1950df346ad9d9cf5ca"
    );

const GOOGLE_END_ENTITY_CERT: [u8; 0x0974] =
    hex_literal::hex!(
        "3082097030820858a00302010202103c8415c8e1e38e7702000000007fd492300d06092a864886f70d01010b05003042310b3009060355040613025553311e301c060355040a1315476f6f676c65205472757374205365727669636573311330110603550403130a47545320434120314f31301e170d3230313032383136313833365a170d3231303132303136313833365a3066310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c65204c4c433115301306035504030c0c2a2e676f6f676c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004928f17ebaacb747f1c091d80bab6397cefca2ceed75053a05a196074295add702ed9298d45937515d53026c4ae3bdede339607b42b7525ad2713f1eb455208a6a382070730820703300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e04160414c2f35a502b0f66ccd7cf4ce9f687b6203f0d3b7c301f0603551d2304183016801498d1f86e10ebcf9bec609f18901ba0eb7d09fd2b306806082b06010505070101045c305a302b06082b06010505073001861f687474703a2f2f6f6373702e706b692e676f6f672f677473316f31636f7265302b06082b06010505073002861f687474703a2f2f706b692e676f6f672f677372322f475453314f312e637274308204c20603551d11048204b9308204b5820c2a2e676f6f676c652e636f6d820d2a2e616e64726f69642e636f6d82162a2e617070656e67696e652e676f6f676c652e636f6d82092a2e62646e2e64657682122a2e636c6f75642e676f6f676c652e636f6d82182a2e63726f7764736f757263652e676f6f676c652e636f6d82182a2e64617461636f6d707574652e676f6f676c652e636f6d82062a2e672e636f820e2a2e6763702e677674322e636f6d82112a2e67637063646e2e677674312e636f6d820a2a2e67677068742e636e820e2a2e676b65636e617070732e636e82162a2e676f6f676c652d616e616c79746963732e636f6d820b2a2e676f6f676c652e6361820b2a2e676f6f676c652e636c820e2a2e676f6f676c652e636f2e696e820e2a2e676f6f676c652e636f2e6a70820e2a2e676f6f676c652e636f2e756b820f2a2e676f6f676c652e636f6d2e6172820f2a2e676f6f676c652e636f6d2e6175820f2a2e676f6f676c652e636f6d2e6272820f2a2e676f6f676c652e636f6d2e636f820f2a2e676f6f676c652e636f6d2e6d78820f2a2e676f6f676c652e636f6d2e7472820f2a2e676f6f676c652e636f6d2e766e820b2a2e676f6f676c652e6465820b2a2e676f6f676c652e6573820b2a2e676f6f676c652e6672820b2a2e676f6f676c652e6875820b2a2e676f6f676c652e6974820b2a2e676f6f676c652e6e6c820b2a2e676f6f676c652e706c820b2a2e676f6f676c652e707482122a2e676f6f676c656164617069732e636f6d820f2a2e676f6f676c65617069732e636e82112a2e676f6f676c65636e617070732e636e82142a2e676f6f676c65636f6d6d657263652e636f6d82112a2e676f6f676c65766964656f2e636f6d820c2a2e677374617469632e636e820d2a2e677374617469632e636f6d82122a2e67737461746963636e617070732e636e820a2a2e677674312e636f6d820a2a2e677674322e636f6d82142a2e6d65747269632e677374617469632e636f6d820c2a2e75726368696e2e636f6d82102a2e75726c2e676f6f676c652e636f6d82132a2e776561722e676b65636e617070732e636e82162a2e796f75747562652d6e6f636f6f6b69652e636f6d820d2a2e796f75747562652e636f6d82162a2e796f7574756265656475636174696f6e2e636f6d82112a2e796f75747562656b6964732e636f6d82072a2e79742e6265820b2a2e7974696d672e636f6d821a616e64726f69642e636c69656e74732e676f6f676c652e636f6d820b616e64726f69642e636f6d821b646576656c6f7065722e616e64726f69642e676f6f676c652e636e821c646576656c6f706572732e616e64726f69642e676f6f676c652e636e8204672e636f820867677068742e636e820c676b65636e617070732e636e8206676f6f2e676c8214676f6f676c652d616e616c79746963732e636f6d820a676f6f676c652e636f6d820f676f6f676c65636e617070732e636e8212676f6f676c65636f6d6d657263652e636f6d8218736f757263652e616e64726f69642e676f6f676c652e636e820a75726368696e2e636f6d820a7777772e676f6f2e676c8208796f7574752e6265820b796f75747562652e636f6d8214796f7574756265656475636174696f6e2e636f6d820f796f75747562656b6964732e636f6d820579742e626530210603551d20041a30183008060667810c010202300c060a2b06010401d67902050330330603551d1f042c302a3028a026a0248622687474703a2f2f63726c2e706b692e676f6f672f475453314f31636f72652e63726c30820104060a2b06010401d6790204020481f50481f200f0007700f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3000001757037f6230000040300483046022100aac1f73dd8213ad0f7cacfb97830908dd1bf945331fde26b369992cd52731ef1022100bcaa58c50418f910ac3aab1b9f4963c86a8abe79a4ce751ad9489008ae8db433007500eec095ee8d72640f92e3c3b91bc712a3696a097b4b6a1a1438e647b2cbedc5f9000001757037f675000004030046304402203534f394062ad3c22a3ee6b4fc4515824331e758179dbc003d1b30714858e7a802206b2f82038e90b0b1497a50adfa02edabc14c72a68f29ef8beebcdeb3aa79c5f9300d06092a864886f70d01010b05000382010100483bacd4bcba6181eaae86db235942cf84c89dd91ec973525eb46a0582b6fad7ef02124c94521e5d92272a4f87f82a23804adacc08f9da02f7f9b4a25f7d3c819a215b9b8f9308b943b0cd6c9121ecb6f9bd6491c20ec8c149fd171a5c13d17cf6bf1b7cfb2031016637d0daa2ce2f419d498abfdde0eb200c0586068789cbbaea3dd6b9e9e6ba124c6c4e9bf00c5bc79df57f91b849a6a8340883b5d2e1a3b00f86b7c56b34ef740a80ebce142c4973241934a5f257b406e4d2159ae0c27a70a88e8e3036b40611234fa7ece6dff1a5ed0dbc118a361879f0f26b6497cc17b36e2750c92ac0e64db12e5a2ac4142a5ca135ef6ea90f82c20a0eb4b4ed1a31d1"
    );

const CLIENT_TRANSCRIPT_HASH: [u8; 32] = [37, 135, 142, 217, 184, 116, 6, 86, 229, 163, 82, 51, 108, 168, 135, 99, 87, 101, 215, 44, 94, 5, 177, 160, 153, 125, 39, 51, 148, 67, 140, 70];

const CLIENT_PUBLIC_KEY: [u8; 0x010E] =
    hex_literal::hex!(
        "3082010a0282010100c24c615adad1640c2e39e295c460f2c795370cfb21cca519f9e6baf15645ca0b256ef8f318491baab9dc7196360b393bc35320354887d6cc822cf6e9d2eacc7fecf8d8e73f0f09bf131a5919e9e9c81e2aecf06d55be1720290853d4f1086b3e103d54d2b454d7c32abce433f6115d267bba246f68847463dfd1d6be904eb18d56885565d6fcf8a60386fc73b5450777e00485ae94d22096afc458d7fbd7c469dd861cab7b914715e093c4f1cc399e5a53010c2b65d5cc3d60fccc2cc5d8b3faa5fefaab551f1de1a93a19a15be9adb3a5c96d2e525a9f696174e6e772857e536b462a61c69a87710b74172c4b318f4842e7d27f7b6e0cbf3f983e3564ab80070203010001"
    );

const CLIENT_SIGNATURE: [u8; 256] =
    hex_literal::hex!(
        "954ced7ddc8fdccbaeb83ee9b3a26a01c37cc74bfcb82b3b181c28ae06588f763cfc491b6869b74968fd7ae017360d8eeaa5bfb69d9c0e3524f14790422f7ccbc9a609880800c5076d6383865cd47986eff4d379bf554b86963ce4bc4706262f48932fd5fa16e73149c1c960f19f5e8d1a8dc5898a9e2de5c0d79a8a0017349f379d23683eec83a07f01c3b83cb4d0f66ae0672efc9723bed0296a82046232dc533988a253bd2b109074172735bad06b98c3863033d2d11ea2d0efc7a3db52c94d2e452882e87559a0e9036768dbc380189b89323294a03ef229943be3fa17095c5a220386c695cf279bc88ff1b017897cbcb231658937eef82adb9a17479429"
    );

const CLIENT_PRIVATE_KEY_MOD: &'static [u8] = &[
    0x00, 0xc2, 0x4c, 0x61, 0x5a, 0xda, 0xd1, 0x64, 0x0c, 0x2e, 0x39, 0xe2, 0x95, 0xc4, 0x60, 0xf2, 0xc7, 0x95, 0x37, 0x0c, 0xfb, 0x21, 0xcc, 0xa5, 0x19, 0xf9, 0xe6, 0xba, 0xf1, 0x56, 0x45, 0xca, 0x0b, 0x25, 0x6e, 0xf8, 0xf3, 0x18, 0x49, 0x1b, 0xaa, 0xb9, 0xdc, 0x71, 0x96, 0x36, 0x0b, 0x39, 0x3b, 0xc3, 0x53, 0x20, 0x35, 0x48, 0x87, 0xd6, 0xcc, 0x82, 0x2c, 0xf6, 0xe9, 0xd2, 0xea, 0xcc, 0x7f, 0xec, 0xf8, 0xd8, 0xe7, 0x3f, 0x0f, 0x09, 0xbf, 0x13, 0x1a, 0x59, 0x19, 0xe9, 0xe9, 0xc8, 0x1e, 0x2a, 0xec, 0xf0, 0x6d, 0x55, 0xbe, 0x17, 0x20, 0x29, 0x08, 0x53, 0xd4, 0xf1, 0x08, 0x6b, 0x3e, 0x10, 0x3d, 0x54, 0xd2, 0xb4, 0x54, 0xd7, 0xc3, 0x2a, 0xbc, 0xe4, 0x33, 0xf6, 0x11, 0x5d, 0x26, 0x7b, 0xba, 0x24, 0x6f, 0x68, 0x84, 0x74, 0x63, 0xdf, 0xd1, 0xd6, 0xbe, 0x90, 0x4e, 0xb1, 0x8d, 0x56, 0x88, 0x55, 0x65, 0xd6, 0xfc, 0xf8, 0xa6, 0x03, 0x86, 0xfc, 0x73, 0xb5, 0x45, 0x07, 0x77, 0xe0, 0x04, 0x85, 0xae, 0x94, 0xd2, 0x20, 0x96, 0xaf, 0xc4, 0x58, 0xd7, 0xfb, 0xd7, 0xc4, 0x69, 0xdd, 0x86, 0x1c, 0xab, 0x7b, 0x91, 0x47, 0x15, 0xe0, 0x93, 0xc4, 0xf1, 0xcc, 0x39, 0x9e, 0x5a, 0x53, 0x01, 0x0c, 0x2b, 0x65, 0xd5, 0xcc, 0x3d, 0x60, 0xfc, 0xcc, 0x2c, 0xc5, 0xd8, 0xb3, 0xfa, 0xa5, 0xfe, 0xfa, 0xab, 0x55, 0x1f, 0x1d, 0xe1, 0xa9, 0x3a, 0x19, 0xa1, 0x5b, 0xe9, 0xad, 0xb3, 0xa5, 0xc9, 0x6d, 0x2e, 0x52, 0x5a, 0x9f, 0x69, 0x61, 0x74, 0xe6, 0xe7, 0x72, 0x85, 0x7e, 0x53, 0x6b, 0x46, 0x2a, 0x61, 0xc6, 0x9a, 0x87, 0x71, 0x0b, 0x74, 0x17, 0x2c, 0x4b, 0x31, 0x8f, 0x48, 0x42, 0xe7, 0xd2, 0x7f, 0x7b, 0x6e, 0x0c, 0xbf, 0x3f, 0x98, 0x3e, 0x35, 0x64, 0xab, 0x80, 0x07
];
const CLIENT_PRIVATE_KEY_EXP: &'static [u8] = &[0x01, 0x00, 0x01];
const CLIENT_PRIVATE_KEY_PMOD: &'static [u8] = &[
    0x61, 0x95, 0x60, 0xf3, 0xf3, 0xa0, 0x64, 0xa2, 0x25, 0x79, 0x57, 0x0e, 0xa7, 0x21, 0x95, 0xed, 0x9d, 0x48, 0x97, 0xd1, 0x6d, 0x49, 0x4d, 0xc6, 0x7d, 0x17, 0x5f, 0xde, 0xa3, 0xd8, 0xcb, 0x3f, 0xcb, 0xde, 0x2f, 0x54, 0x50, 0x67, 0x2f, 0x69, 0x10, 0x8d, 0xe1, 0xd2, 0x72, 0x74, 0x32, 0x9b, 0x8c, 0x5f, 0x2c, 0x76, 0xf6, 0x65, 0x9b, 0x00, 0xfd, 0x84, 0x3d, 0xc2, 0x73, 0xf7, 0x0f, 0x1c, 0x54, 0xd5, 0x2a, 0x83, 0x01, 0xcd, 0xb8, 0xb4, 0x69, 0x90, 0xbb, 0x1d, 0x63, 0xb8, 0xd1, 0x94, 0x2d, 0x34, 0xf1, 0x0f, 0xc8, 0x97, 0x7f, 0x1f, 0xdc, 0xdb, 0xdc, 0xd6, 0xbe, 0xf3, 0xde, 0x80, 0xbe, 0x41, 0x3f, 0x5f, 0xcf, 0xc8, 0x28, 0xd1, 0x51, 0x9e, 0xaa, 0xf2, 0x59, 0xec, 0xa0, 0x9f, 0x1a, 0x57, 0x03, 0xc3, 0x9c, 0x77, 0xa1, 0xc9, 0x23, 0x79, 0x4d, 0x64, 0x4a, 0x2f, 0xeb, 0xc5, 0xd3, 0x38, 0x2c, 0x6d, 0xf6, 0xa6, 0xa9, 0xe7, 0x0a, 0x79, 0x05, 0xfa, 0x2a, 0x85, 0xc5, 0x9d, 0xf4, 0x91, 0xef, 0x34, 0xad, 0xb5, 0x64, 0xc5, 0x75, 0x8a, 0x36, 0x8f, 0x95, 0x25, 0xe9, 0x71, 0x0d, 0xa8, 0xe1, 0xea, 0xc3, 0xb4, 0xaa, 0xe7, 0x54, 0x54, 0xef, 0x72, 0x12, 0xa5, 0x14, 0x27, 0xec, 0x70, 0x12, 0x14, 0xdf, 0x65, 0xb3, 0xf5, 0xbc, 0x91, 0xe1, 0x36, 0x31, 0x1a, 0xdf, 0x7d, 0x58, 0x05, 0xb6, 0xe3, 0x48, 0xf2, 0x42, 0x89, 0x25, 0x29, 0x42, 0x0b, 0x5d, 0x8d, 0x0b, 0x76, 0x28, 0x0f, 0xaf, 0x56, 0x22, 0x94, 0x12, 0x8f, 0x76, 0x91, 0x49, 0xa6, 0xa4, 0xe3, 0x54, 0x17, 0x9e, 0xeb, 0xa6, 0x1b, 0xe5, 0x97, 0xde, 0x4e, 0x29, 0x8d, 0x7d, 0x5c, 0x18, 0x34, 0x29, 0x21, 0xd2, 0x7d, 0x14, 0x0b, 0xa1, 0x49, 0xb5, 0xe0, 0xc6, 0x30, 0x31, 0x80, 0xdc, 0x6a, 0x59, 0xb9
];
const CLIENT_PRIME_1: &'static [u8] = &[
    0x00, 0xec, 0xe1, 0x6f, 0x5d, 0x7a, 0xed, 0x7b, 0x1a, 0xac, 0xce, 0x02, 0x91, 0xb4, 0x07, 0xcf, 0xc4, 0x2b, 0xcf, 0x2a, 0x37, 0x59, 0x43, 0x46, 0x1a, 0x55, 0xc2, 0x13, 0x89, 0x3c, 0xd5, 0xd6, 0xef, 0xed, 0x12, 0x9f, 0xc3, 0x36, 0x95, 0xd2, 0x6e, 0xf7, 0xca, 0x62, 0x9c, 0x71, 0x3d, 0x78, 0x3a, 0x4c, 0xe2, 0x5d, 0x07, 0x6e, 0x67, 0x53, 0xc3, 0xe7, 0x02, 0x58, 0x34, 0x25, 0xab, 0x67, 0xd4, 0x35, 0x92, 0x26, 0x4a, 0x3f, 0x1b, 0xc4, 0x43, 0xcd, 0x71, 0x3a, 0x8f, 0x9a, 0x2e, 0x44, 0xf6, 0x5a, 0x40, 0xf8, 0x32, 0x11, 0x39, 0xd4, 0x31, 0x35, 0xa1, 0xd7, 0x2d, 0x5d, 0xa5, 0xed, 0x24, 0x53, 0x32, 0xce, 0xb6, 0xb6, 0x12, 0xc6, 0xeb, 0xfd, 0x5b, 0x86, 0x21, 0xf7, 0xaf, 0x2e, 0x29, 0xb0, 0xed, 0x4d, 0x71, 0x3e, 0x82, 0x28, 0x74, 0xd5, 0x64, 0x59, 0xba, 0xa6, 0x59, 0xd7, 0x9b
];
const CLIENT_PRIME_2: &'static [u8] = &[
    0x00, 0xd1, 0xfb, 0x16, 0x0c, 0xf0, 0xa3, 0x9a, 0x56, 0xdc, 0x3d, 0x82, 0xc6, 0x69, 0xed, 0x1d, 0x6a, 0x6f, 0xf9, 0xf0, 0x27, 0x3f, 0x96, 0x15, 0x39, 0x30, 0x84, 0x93, 0x75, 0x67, 0x31, 0xc9, 0x55, 0x84, 0x14, 0x13, 0x54, 0x39, 0xc1, 0x7c, 0x02, 0x77, 0x2b, 0x56, 0x49, 0x2c, 0xca, 0xe5, 0x16, 0xb5, 0xa1, 0x22, 0x49, 0xd6, 0xfa, 0x96, 0xd7, 0xb8, 0xaf, 0x34, 0xd3, 0x00, 0xc0, 0x42, 0x2f, 0x73, 0x0d, 0xb1, 0xd0, 0xc8, 0x11, 0xc6, 0x16, 0x79, 0xde, 0x83, 0xcd, 0x53, 0x21, 0x9b, 0x58, 0xc5, 0xee, 0x35, 0x55, 0xb6, 0x8f, 0x83, 0xc9, 0x23, 0x15, 0x98, 0xe0, 0xb5, 0x6f, 0x3a, 0x3d, 0x0c, 0x06, 0xa8, 0x32, 0x16, 0x0f, 0xde, 0x66, 0xad, 0x44, 0x76, 0xcd, 0x4a, 0x7a, 0x3d, 0xcb, 0x2c, 0x83, 0x3e, 0xf7, 0x50, 0x94, 0xa2, 0x2b, 0x61, 0xb5, 0xb6, 0x02, 0x01, 0x24, 0x7e, 0x05
];
