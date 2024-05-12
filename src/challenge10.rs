use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use thiserror::Error;

use super::{
    decrypt_aes_128_ecb, fixed_xor, pkcs7_padding, remove_pkcs7_padding, Aes128EcbError,
    Pkcs7PaddingError,
};

/// Encrypt plaintext using AES-128-ECB with the key.
pub fn encrypt_aes_128_ecb(key: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, Aes128EcbError> {
    if plaintext.len() == 0 || plaintext.len() % 16 != 0 {
        return Err(Aes128EcbError::InvalidByteLength);
    }

    let cipher = Aes128::new(&GenericArray::clone_from_slice(key));

    let mut blocks = Vec::new();
    plaintext
        .chunks_exact(16)
        .for_each(|chunk| blocks.push(GenericArray::clone_from_slice(chunk)));

    cipher.encrypt_blocks(&mut blocks);
    Ok(blocks.iter().flatten().map(|&b| b).collect())
}

#[derive(Debug, Error)]
pub enum Aes128EcbWithPkcs7Error {
    #[error(transparent)]
    Aes128Ecb(#[from] Aes128EcbError),

    #[error(transparent)]
    Pkcs7(#[from] Pkcs7PaddingError),
}

/// Encrypt PKCS#7 padded plaintext using AES-128-ECB with the key.
pub fn encrypt_aes_128_ecb_with_pkcs7(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let plaintext = pkcs7_padding(plaintext, 16);
    encrypt_aes_128_ecb(key, &plaintext).unwrap()
}

/// Decrypt AES-128-ECB encrypted ciphertext using the key, and remove PKCS#7 padding.
pub fn decrypt_aes_128_ecb_with_pkcs7(
    key: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Aes128EcbWithPkcs7Error> {
    let plaintext = decrypt_aes_128_ecb(key, ciphertext)?;
    let plaintext = remove_pkcs7_padding(&plaintext, 16)?;
    Ok(plaintext)
}

#[derive(Debug, Error)]
pub enum Aes128CbcError {
    #[error("Invalid byte length, must be multiple of 16")]
    InvalidByteLength,
}

pub fn encrypt_aes_128_cbc(
    key: &[u8; 16],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, Aes128CbcError> {
    if plaintext.len() == 0 || plaintext.len() % 16 != 0 {
        return Err(Aes128CbcError::InvalidByteLength);
    }

    let mut last_ciphertext_block = iv.to_vec();
    let mut ciphertext_blocks = Vec::new();
    for chunk in plaintext.chunks_exact(16) {
        // XOR with previous ciphertext block, unless first one then XOR with IV.
        let xor_block = fixed_xor(&chunk, &last_ciphertext_block).unwrap();
        // Encrypt and collect ciphertext blocks
        ciphertext_blocks.push(encrypt_aes_128_ecb(key, &xor_block).unwrap());
        // Reassign last ciphertext block
        last_ciphertext_block = ciphertext_blocks.last().unwrap().clone()
    }

    Ok(ciphertext_blocks.iter().flatten().map(|&b| b).collect())
}

pub fn decrypt_aes_128_cbc(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Aes128CbcError> {
    if ciphertext.len() == 0 || ciphertext.len() % 16 != 0 {
        return Err(Aes128CbcError::InvalidByteLength);
    }

    let mut last_ciphertext_block = iv.to_vec();
    let mut plaintext = Vec::new();
    for chunk in ciphertext.chunks_exact(16) {
        // Decrypt ciphertext block
        let xor_block = decrypt_aes_128_ecb(key, chunk).unwrap();
        // XOR decrypted block with previous ciphertext block
        plaintext.append(&mut fixed_xor(&xor_block, &last_ciphertext_block).unwrap());
        // Reassign previous ciphertext block
        last_ciphertext_block = chunk.to_vec();
    }

    Ok(plaintext)
}

pub fn encrypt_aes_128_cbc_with_pkcs7(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let plaintext = pkcs7_padding(plaintext, 16);
    encrypt_aes_128_cbc(key, iv, &plaintext).unwrap()
}

#[derive(Debug, Error)]
pub enum Aes128CbcWithPkcs7Error {
    #[error(transparent)]
    Aes128Cbc(#[from] Aes128CbcError),

    #[error(transparent)]
    Pkcs7(#[from] Pkcs7PaddingError),
}

pub fn decrypt_aes_128_cbc_with_pkcs7(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Aes128CbcWithPkcs7Error> {
    let plaintext = decrypt_aes_128_cbc(key, iv, ciphertext)?;
    let plaintext = remove_pkcs7_padding(&plaintext, 16)?;
    Ok(plaintext)
}

#[cfg(test)]
mod test {
    use super::super::decode_base64_from_file;
    use super::*;

    #[test]
    fn aes_128_ecb_with_pkcs7() {
        let key: [u8; 16] = "Hello World 123!".as_bytes().try_into().unwrap();
        let original_text = "This is a secret message".as_bytes();

        let ciphertext = encrypt_aes_128_ecb_with_pkcs7(&key, original_text);
        let plaintext =
            decrypt_aes_128_ecb_with_pkcs7(&key, &ciphertext).expect("Unexpected error");

        assert_eq!(plaintext, original_text);
    }

    #[test]
    fn aes_128_cbc() {
        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();
        let iv: [u8; 16] = "Hello World 123!".as_bytes().try_into().unwrap();
        let original_text = pkcs7_padding("This is a secret message".as_bytes(), 16);

        let ciphertext = encrypt_aes_128_cbc(&key, &iv, &original_text).expect("Unexpected error");
        let plaintext = decrypt_aes_128_cbc(&key, &iv, &ciphertext).expect("Unexpected error");

        assert_eq!(plaintext, original_text)
    }

    #[test]
    fn decrypt_aes_128_cbc_ok() {
        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();
        let iv = [0u8; 16];

        let buf = decode_base64_from_file("data/challenge10.txt").expect("Cannot read file");
        let plaintext = decrypt_aes_128_cbc(&key, &iv, &buf).expect("Unexpected error");
        let plaintext = String::from_utf8(plaintext).unwrap();

        println!("{plaintext}");
        assert!(plaintext.contains("Play that funky music"));
    }
}
