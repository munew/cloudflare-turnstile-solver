use crate::reverse::xtea::XTEA;
use base64::alphabet::Alphabet;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use byteorder::BE;
use num::bigint::Sign;
use num::{BigInt, Num};
use once_cell::sync::Lazy;
use crate::reverse::lz::lz_compress;

pub fn encrypt_payload(input: &str, charset: &str, random_bytes: &mut [u8; 128]) -> String {
    assert!(charset.len() >= 64);
    
    let mut output = Vec::new();

    // Overwrite first rand byte to 0 (probably done because of how derivation works)
    random_bytes[0] = 0;
    
    let mut compressed = lz_compress(input);
    
    // Calculate and append necessary padding for 8 bytes blocks
    let padding = (8 - compressed.len() % 8) % 8;
    compressed.extend(vec![0; padding]);

    // Write derived bytes and pad byte (0..127=derived 128=pad)
    let derived_bytes = derive_bytes_with_public_key(random_bytes);
    output.extend_from_slice(&derived_bytes);
    output.push(padding as u8);
    
    // derived.slice(pad*9+40, pad*9+40+16)
    let key_index = padding * 9 + 40;
    let key = &random_bytes[key_index..key_index + 16];

    output.extend_from_slice(&turnstile_xtea(compressed, key));
    
    // Base64 the final output using the custom charset
    // It should not have any padding.
    turnstile_base64_encode(&output, charset)
}

// Creates a xtea instance with provided key as argument
// Then for each block (8 bytes), enciphers 2 emptied blocks except last byte which will respectively be curr_block and curr_block+1 (u8)
// Then concatenates the 2 enciphered blocks to make our xtea block key
// Finally, use that xtea instance to encipher our block.
fn turnstile_xtea(mut input: Vec<u8>, key: &[u8]) -> Vec<u8> {
    assert_eq!(key.len(), 16); // xtea key should be 16 bytes long
    assert_eq!(input.len() % 8, 0); // input should be a multiple of 8 bytes
    
    let xtea = XTEA::new(&u8_to_u32_be(<&[u8; 16]>::try_from(key).unwrap()));
    let mut res = Vec::<u8>::new();
    let mut curr: usize = 0;
    
    while input.len() > 0 {
        let first = vec![0, 0, 0, 0, 0, 0, 0, (curr & 255) as u8];
        let mut first_output = vec![0u8; first.len()].into_boxed_slice();
        xtea.encipher_u8slice::<BE>(&first, &mut first_output);

        let second = vec![0, 0, 0, 0, 0, 0, 0, ((curr + 1) & 255) as u8];
        let mut second_output = vec![0u8; second.len()].into_boxed_slice();
        xtea.encipher_u8slice::<BE>(&second, &mut second_output);

        let mut key_stream = first_output.to_vec();
        key_stream.extend(&second_output);

        let key_array: [u8; 16] = key_stream
            .as_slice()
            .try_into()
            .expect("slice with incorrect length");
        
        let xtea2 = XTEA::new(&u8_to_u32_be(&key_array));

        // Block should ALWAYS be 8 bytes
        let b = input.drain(0..8).collect::<Vec<u8>>();
        let mut decipher = vec![0u8; 8].into_boxed_slice();
        xtea2.encipher_u8slice::<BE>(&b, &mut decipher);

        res.extend(decipher);
        curr += 1;
    }
    
    res
}

// Encode base64 inputs using the custom charset.
// We strip the last char as base64 requires only 64 chars and not 65.
// We sadly can't cache the engine since the charset changes.
fn turnstile_base64_encode(input: &[u8], charset: &str) -> String {
    let alphabet = Alphabet::new(&charset[0..64]).unwrap();
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(false);
    let engine = GeneralPurpose::new(&alphabet, config);
    
    engine.encode(input)
}

fn u8_to_u32_be(bytes: &[u8; 16]) -> [u32; 4] {
    let mut result = [0u32; 4];
    for i in 0..4 {
        result[i] = u32::from_be_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    result
}

// Asymmetric encryption public key used to derive random bytes
static PUBLIC_KEY: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_str_radix(
        "00e9d3dca1328a49ad3403e4badda37a6a13610b608b5099839e1074e720f5a33b2ebd8c2ffd12c09be0015a4635aa9d2022d8f72f90ed11610c3742b0baef5b7da73d7e79aff6cdbdeab72492ce0a858e4c1f4c27a14ebbb4ce3beacfda982fe74463e76f654aab0c597d5e73686ea149023e8f60ae6365a30055fe2c5eb2ebfb",
        16
    ).unwrap()
});

fn derive_bytes_with_public_key(bytes: &[u8; 128]) -> [u8; 128] {
    let exp = BigInt::from(65537);
    let random_value = BigInt::from_bytes_be(Sign::Plus, bytes);
    let encrypted = random_value.modpow(&exp, &PUBLIC_KEY);
    let (_, mut derived_key) = encrypted.to_bytes_be();

    // We left-pad our derived key with 0s to make it 128 bytes long. (Yes, it sometimes happens)
    let mut left_padded = vec![0u8; 128 - derived_key.len()];
    left_padded.append(&mut derived_key);

    // The unwrap should never ever fail, theoretically.
    <[u8; 128]>::try_from(left_padded).unwrap()
}