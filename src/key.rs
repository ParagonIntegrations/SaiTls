use hkdf::Hkdf;
use sha2::{ Digest, Sha256, Sha384, Sha512 };
use sha2::digest::{BlockInput, FixedOutput, Reset, Update};
use generic_array::{ GenericArray, ArrayLength };
use heapless::{ String, Vec, consts::* };

use crate::buffer::TlsBuffer;

use core::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct HkdfLabel<'a> {
    // Length of hash function
    pub length: u16,
    // Label vector: "tls13 " + label
    pub label_length: u8,
    pub label: &'a [u8],
    // Context vector: Hashed message
    pub context_length: u8,
    pub context: &'a [u8],
}

// Implementation of Derive-Secret function in RFC8446
pub fn derive_secret<Hash>(
    hkdf: &Hkdf<Hash>,
    label: &str,
    hash: Hash
) -> GenericArray<u8, Hash::OutputSize>
where
    Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone,
    Hash::OutputSize: ArrayLength<u8>,
{
    // Build a string using heapless
    // label size:
    //      prefix: "tls13 " => 6 chars
    //      suffix: at most 12 chars as per RFC8446, section 7.1
    let mut label_string: String<U32> = String::new();
    label_string.push_str("tls13 ").unwrap();
    label_string.push_str(label);

    let length = u16::try_from(Hash::output_size()).unwrap();
    let label_length = u8::try_from(label_string.len()).unwrap();

    let hkdf_label = HkdfLabel {
        length,
        label_length,
        label: label_string.as_ref(),
        context_length: u8::try_from(length).unwrap(),
        context: &hash.finalize(),
    };

    // Build info from HKDF label using Buffer
    //      length: 2 bytes,
    //      label_vec: 18 bytes (label) + 1 byte (len)
    //      context_vec: 48 bytes for SHA384 + 1 byte (len)
    let mut array = [0; 100];
    let mut buffer = TlsBuffer::new(&mut array);
    buffer.enqueue_hkdf_label(hkdf_label);
    let info: &[u8] = buffer.into();

    // Define output key material (OKM), dynamically sized by hash
    let mut okm: GenericArray<u8, Hash::OutputSize> = GenericArray::default();
    hkdf.expand(info, &mut okm).unwrap();
    okm
}

// Implementation of HKDF-Expand-Label function in RFC8446
// Secret is embedded inside hkdf through salt and input key material (IKM)
pub fn hkdf_expand_label<Hash>(
    hkdf: &Hkdf<Hash>,
    label: &str,
    context: &str,
    okm: &mut [u8],
)
where
    Hash: Update + BlockInput + FixedOutput + Reset + Default + Clone,
{
    // Build a string using heapless
    // label size:
    //      prefix: "tls13 " => 6 chars
    //      suffix: at most 12 chars as per RFC8446, section 7.1
    let mut label_string: String<U32> = String::new();
    label_string.push_str("tls13 ").unwrap();
    label_string.push_str(label);
    let label_length = u8::try_from(label_string.len()).unwrap();

    let context_slice = context.as_bytes();
    let context_length = u8::try_from(context_slice.len()).unwrap();

    let length = u16::try_from(okm.len()).unwrap();

    // Build HKDF label
    let hkdf_label = HkdfLabel {
        length,
        label_length,
        label: label_string.as_ref(),
        context_length: context_length,
        context: context_slice,
    };

    // Build info from HKDF label using Buffer
    //      length: 2 bytes,
    //      label_vec: 18 bytes (label) + 1 byte (len)
    //      context_vec: 48 bytes for SHA384 + 1 byte (len)
    let mut array = [0; 100];
    let mut buffer = TlsBuffer::new(&mut array);
    buffer.enqueue_hkdf_label(hkdf_label).unwrap();
    let info: &[u8] = buffer.into();

    hkdf.expand(info, okm).unwrap();
}
