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
use heapless::Vec;
use hkdf::Hkdf;

use rand::rngs::OsRng;

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
        )
    };

    tls_socket.tcp_connect(
        &mut sockets,
        (Ipv4Address::new(192, 168, 1, 125), 1883),
        49600
    ).unwrap();

//    tls_socket.tls_connect(&mut sockets).unwrap();
    simple_logger::SimpleLogger::new().init().unwrap();

    let (_, certificate) = parse_asn1_der_certificate(&CA_SIGNED_CERT).unwrap();
    println!("Certificate print: {:?}", certificate);

    let modulus = [
        0x00, 0xe1, 0x64, 0x42, 0x1f, 0x32, 0x2c, 0xa2, 0x81, 0x3a, 0x6f, 0x9d, 0x4e, 0x6d, 0xa7, 0xc9, 0xed, 0xb9, 0x47, 0x3e, 0xd8, 0x98, 0xe6, 0xba, 0xab, 0x07, 0x93, 0xb3, 0xc5, 0x80, 0x62, 0x7e, 0xb7, 0xe3, 0x9a, 0xfb, 0x9c, 0xf4, 0x0c, 0xc7, 0x49, 0x08, 0x73, 0x45, 0xe8, 0x94, 0xff, 0xb1, 0xe7, 0x52, 0xb6, 0x77, 0xa7, 0x53, 0x49, 0x0b, 0xf3, 0xe6, 0x13, 0x4a, 0x79, 0xd7, 0xef, 0x53, 0x7c, 0x8d, 0x84, 0x5b, 0xf3, 0x30, 0x6d, 0x4d, 0x43, 0x14, 0xa0, 0xc9, 0x8b, 0x86, 0x17, 0x16, 0x8a, 0x09, 0x60, 0xa9, 0xdb, 0x76, 0x8f, 0x5c, 0x58, 0x92, 0xf3, 0x63, 0xdb, 0x39, 0x82, 0xa7, 0x4a, 0x79, 0x08, 0x29, 0x1d, 0x94, 0x3c, 0xec, 0x11, 0x46, 0x70, 0xf8, 0xd1, 0xe4, 0xc2, 0x6f, 0x9d, 0x40, 0x8d, 0x8a, 0x29, 0x2e, 0x2b, 0x82, 0xd6, 0x1b, 0x0f, 0xbd, 0x49, 0xe4, 0xc9, 0xfb, 0xc3, 0x81, 0x29, 0x7f, 0x99, 0x07, 0x99, 0x5a, 0x28, 0x46, 0xf7, 0xdd, 0xca, 0xb2, 0x4c, 0xce, 0x21, 0x01, 0x24, 0xfc, 0xfe, 0x8f, 0xea, 0x73, 0x36, 0x39, 0xdf, 0xa0, 0x6c, 0x43, 0xf5, 0x3c, 0x74, 0xb3, 0x17, 0x00, 0xfd, 0xb4, 0xa2, 0x82, 0x1e, 0xed, 0xdf, 0x22, 0x2a, 0x35, 0x6d, 0xf7, 0x8a, 0x4d, 0xc8, 0x19, 0xb9, 0xd3, 0x88, 0x29, 0x10, 0x8e, 0xae, 0x30, 0xf2, 0x23, 0xce, 0x3b, 0xce, 0xe0, 0x7c, 0x5e, 0x52, 0xa1, 0x1f, 0xc1, 0x59, 0xcc, 0x14, 0xf6, 0x6f, 0xf1, 0xa6, 0xbb, 0xfd, 0x9b, 0x66, 0x96, 0x89, 0xbb, 0xd4, 0x0b, 0x9e, 0x5f, 0xac, 0xf0, 0x1d, 0x88, 0xa6, 0x27, 0x53, 0x48, 0xf2, 0x12, 0x54, 0x43, 0xf8, 0x92, 0x42, 0xcd, 0x6e, 0x00, 0x54, 0x67, 0x55, 0x6f, 0xfa, 0x38, 0x30, 0x7b, 0xea, 0xaa, 0x85, 0x9b, 0x31, 0xbf, 0x78, 0xb8, 0x2a, 0x97, 0x77, 0xd0, 0x23
    ];

    let exponent = [1, 0, 1];

    let rsa_public_key = rsa::RSAPublicKey::new(
        rsa::BigUint::from_bytes_be(&modulus),
        rsa::BigUint::from_bytes_be(&exponent)
    ).unwrap();

    let ca_public_key = smoltcp_tls::session::CertificatePublicKey::RSA {
        cert_rsa_public_key: rsa_public_key
    };

    certificate.validate_signature_with_trusted(&ca_public_key).unwrap();
    println!("Certificate should be trusted");

}

const RSA_PSS_CERT: [u8; 0x3AB] =
    hex_literal::hex!("308203a73082028fa00302010202146642be8f709457f9cd6eed72051c240a5565138c300d06092a864886f70d01010a30003063310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311c301a06035504030c136578616d706c652e756c666865696d2e6e6574301e170d3230313130343039313535325a170d3231313130343039313535325a3063310b30090603550406130255533113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464311c301a06035504030c136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100b5a347b654ca0bad8d56990e70aa7411b78dedc9fd9a6760ee936ea01486238538dbc4d0bc95a1a5f060b6296ba67001f103cfd918ad1ec33a1a680d4e8283a24300391e9a53cd6641fc51f0a984c3cd16542b934a0ec8c3447782542628320d6c24988cf0b7b19bbaba91f1999968def724d8e65b624fbb9826208aece1ee90badda7c6b8a97fc4085299f9d32661a06bc67d2d662e0efcee1df5b6dc1d02e56929d8976441456d0fe50314c9861e9845f75f5dc2ca9828089b5d4bd109d1e8ada8986c5bd68ee004a7bfcb932768023e11fe8e299b25b8774ed8bdbb0f644ddaa83df1ff4e84bfc18d3b815decb5ca4f1db1125df98dba94e4ef5570ec5a510203010001a3533051301d0603551d0e04160414050928eff30f3094f01ddb09f1d7a9193addf854301f0603551d23041830168014050928eff30f3094f01ddb09f1d7a9193addf854300f0603551d130101ff040530030101ff300d06092a864886f70d01010a300003820101002d14281587dc33d4559e77852d17fade1a9f3f0e5af847bde80c921be360d6e3b598dfb50aad706de3832841798b66736b9296a83c06e0078dceabc39760a5bf5eb7a7287859b22e9beb7ebb928b99034d155fd12307ee541ea53979bb8afb62db233dfcf1e16afea5eac33817b8cbb13841cb89e9b65a5a4b08a6c6e3d1e0036bc9576b90cf62437e3ef985f02b88be4e6863068c9bc45dd473763f4cdcfc3bfb8a90d7b3225b67a3a39c6ac446de55596dc135221b4383773ddd9efdcca48f389af9c1c0547e0ada1c14153fc38e02c95e4c37da45af1e6d3b0a6cafb603d95a1c887384b476caf60783835a150ee7fd22b6838ce19adcb2e59572c6349703");

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
