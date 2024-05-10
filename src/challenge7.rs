use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128;

/// Decrypt AES-128-ECB encrypted ciphertext using the key.
pub fn decrypt_aes_128_ecb(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(&GenericArray::clone_from_slice(key));

    let mut blocks = Vec::new();
    ciphertext
        .chunks_exact(16)
        .for_each(|chunk| blocks.push(GenericArray::clone_from_slice(chunk)));

    cipher.decrypt_blocks(&mut blocks);
    blocks.iter().flatten().map(|&b| b).collect()
}

#[cfg(test)]
mod test {
    use super::super::decode_base64_from_file;
    use super::*;

    #[test]
    fn decrypt_aes_128_ecb_ok() {
        let ciphertext = decode_base64_from_file("data/challenge7.txt").expect("Unexpected error");
        let key = "YELLOW SUBMARINE";

        let plaintext = decrypt_aes_128_ecb(key.as_bytes(), &ciphertext);
        let plaintext = String::from_utf8(plaintext).unwrap();

        println!("{plaintext}");
        assert!(plaintext.contains("Play that funky music"));
    }
}
