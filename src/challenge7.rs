use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Aes128EcbError {
    #[error("Invalid byte length, must be multiple of 16")]
    InvalidByteLength,
}

/// Decrypt AES-128-ECB encrypted ciphertext using the key.
pub fn decrypt_aes_128_ecb(key: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, Aes128EcbError> {
    if ciphertext.len() == 0 || ciphertext.len() % 16 != 0 {
        return Err(Aes128EcbError::InvalidByteLength);
    }

    let cipher = Aes128::new(&GenericArray::clone_from_slice(key));

    let mut blocks = Vec::new();
    ciphertext
        .chunks_exact(16)
        .for_each(|chunk| blocks.push(GenericArray::clone_from_slice(chunk)));

    cipher.decrypt_blocks(&mut blocks);
    Ok(blocks.iter().flatten().map(|&b| b).collect())
}

#[cfg(test)]
mod test {
    use super::super::decode_base64_from_file;
    use super::*;

    #[test]
    fn decrypt_aes_128_ecb_ok() {
        let key: [u8; 16] = "YELLOW SUBMARINE".as_bytes().try_into().unwrap();
        let ciphertext = decode_base64_from_file("data/challenge7.txt").expect("Unexpected error");

        let plaintext = decrypt_aes_128_ecb(&key, &ciphertext).expect("Unexpected error");
        let plaintext = String::from_utf8(plaintext).unwrap();

        println!("{plaintext}");
        assert!(plaintext.contains("Play that funky music"));
    }
}
