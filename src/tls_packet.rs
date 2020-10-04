use byteorder::{ByteOrder, NetworkEndian, BigEndian};
use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;
use core::convert::TryFrom;

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum TlsContentType {
	Invalid = 0,
	ChangeCipherSpec = 20,
	Alert = 21,
	Handshake = 22,
	ApplicationData = 23
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub(crate) enum TlsVersion {
	Tls10 = 0x0301,
	Tls11 = 0x0302,
	Tls12 = 0x0303,
	Tls13 = 0x0304,
}

#[derive(Clone, Copy)]
pub(crate) struct TlsRepr<'a, 'b> {
	pub(crate) content_type: TlsContentType,
	pub(crate) version: TlsVersion,
	pub(crate) length: u16,
	pub(crate) payload: Option<&'a[u8]>,
	pub(crate) handshake: Option<HandshakeRepr<'a, 'b>>
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub(crate) enum HandshakeType {
	ClientHello = 1,
	ServerHello = 2,
	NewSessionTicket = 4,
	EndOfEarlyData = 5,
	EncryptedExtensions = 8,
	Certificate = 11,
	CertificateRequest = 13,
	CertificateVerify = 15,
	Finished = 20,
	KeyUpdate = 24,
	MessageHash = 254,
}

#[derive(Clone, Copy)]
pub(crate) struct HandshakeRepr<'a, 'b> {
	pub(crate) msg_type: HandshakeType,
	pub(crate) length: u32,
	pub(crate) handshake_data: HandshakeData<'a, 'b>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub(crate) enum CipherSuite {
	TLS_AES_128_GCM_SHA256 = 0x1301,
	TLS_AES_256_GCM_SHA384 = 0x1302,
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
	TLS_AES_128_CCM_SHA256 = 0x1304,
	TLS_AES_128_CCM_8_SHA256 = 0x1305,
}

#[derive(Clone, Copy)]
pub(crate) struct ClientHello<'a, 'b> {
	pub(crate) version: TlsVersion,         // Legacy: Must be Tls12 (0x0303)
	pub(crate) random: [u8; 32],
	pub(crate) session_id_length: u8,       // Legacy: Keep it 32
	pub(crate) session_id: [u8; 32],        // Legacy: Fill this with an unpredictable value
	pub(crate) cipher_suites_length: u16,
	pub(crate) cipher_suites: &'a[CipherSuite],
	pub(crate) compression_method_length: u8,   // Legacy: Must be 1, to contain a byte
	pub(crate) compression_methods: u8,         // Legacy: Must be 1 byte of 0
	pub(crate) extension_length: u16,
	pub(crate) extensions: &'a[Extension<'b>],
}

#[derive(Clone, Copy)]
pub(crate) enum HandshakeData<'a, 'b> {
	Uninitialized,
	ClientHello(ClientHello<'a, 'b>),
	ServerHello(ServerHello<'a, 'b>),
}

impl<'a, 'b> ClientHello<'a, 'b> {
	pub(crate) fn get_length(&self) -> u32 {
		let mut length :u32 = 2;                    // TlsVersion size
		length += 32;      // Random size
		length += 1;                                     // Legacy session_id length size
		length += 32;          // Legacy session_id size
		length += 2;                                     // Cipher_suites_length size
		length += (self.cipher_suites.len() as u32) * 2;
		length += 1;
		length += 1;
		length += 2;
		for extension in self.extensions.iter() {
			length += (extension.get_length() as u32);
		}
		length
	}
}

#[derive(Clone, Copy)]
pub(crate) struct ServerHello<'a, 'b> {
	pub(crate) version: TlsVersion,
	pub(crate) random: [u8; 32],
	pub(crate) session_id_echo_length: u8,
	pub(crate) session_id_echo: [u8; 32],
	pub(crate) cipher_suite: CipherSuite,
	pub(crate) compression_method: u8,     // Always 0
	pub(crate) extension_length: u16,
	pub(crate) extensions: &'a[Extension<'b>],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub(crate) enum ExtensionType {
	ServerName = 0,
	MaxFragmentLength = 1,
	StatusRequest = 5,
	SupportedGroups = 10,
	SignatureAlgorithms = 13,
	UseSRTP = 14,
	Heartbeat = 15,
	ApplicationLayerProtocolNegotiation = 16,
	SignedCertificateTimestamp = 18,
	ClientCertificateType = 19,
	ServerCertificateType = 20,
	Padding = 21,
	PreSharedKey = 41,
	EarlyData = 42,
	SupportedVersions = 43,
	Cookie = 44,
	PSKKeyExchangeModes = 45,
	CertificateAuthorities = 47,
	OIDFilters = 48,
	PostHandshakeAuth = 49,
	SignatureAlgorithmsCert = 50,
	KeyShare = 51,
}

impl ExtensionType {
	pub(crate) fn get_length(&self) -> u16 {
		return 2;
	}
}

#[derive(Clone, Copy)]
pub(crate) struct Extension<'a> {
	pub(crate) extension_type: ExtensionType,
	pub(crate) length: u16,
	pub(crate) extension_data: &'a[u8],
}

impl<'a> Extension<'a> {
	pub(crate) fn get_length(&self) -> u16 {
		self.extension_type.get_length() + 2 + (self.extension_data.len() as u16)
	}
}
