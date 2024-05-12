use rand::{Rng, RngCore};

use crate::{encrypt_aes_128_cbc_with_pkcs7, encrypt_aes_128_ecb_with_pkcs7};

fn random_aes_128_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn random_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let bytes = rng.gen::<[u8; 32]>();
    let num = rng.gen_range(5..=10);

    bytes[..num].to_vec()
}

fn random_pad(buf: &[u8]) -> Vec<u8> {
    let mut result = random_bytes();
    result.append(&mut buf.to_vec());
    result.append(&mut random_bytes());
    result
}

pub enum EncryptAes128Mode {
    Random,
    Ecb,
    Cbc,
}

pub fn random_encrypt_aes_128(plaintext: &[u8], mode: EncryptAes128Mode) -> Vec<u8> {
    let key = random_aes_128_key();
    let plaintext = random_pad(plaintext);

    match mode {
        EncryptAes128Mode::Random => {
            let use_cbc = rand::thread_rng().gen_bool(0.5);
            if use_cbc {
                encrypt_aes_128_cbc_with_pkcs7(&key, &random_aes_128_key(), &plaintext)
            } else {
                encrypt_aes_128_ecb_with_pkcs7(&key, &plaintext)
            }
        }
        EncryptAes128Mode::Ecb => encrypt_aes_128_ecb_with_pkcs7(&key, &plaintext),
        EncryptAes128Mode::Cbc => {
            encrypt_aes_128_cbc_with_pkcs7(&key, &random_aes_128_key(), &plaintext)
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::*;

    fn is_encryption_mode_ecb(ciphertext: &[u8]) -> bool {
        let mut set = HashMap::new();
        for chunk in ciphertext.chunks_exact(16) {
            if set.contains_key(chunk) {
                return true;
            }

            set.insert(chunk, true);
        }

        false
    }

    #[test]
    fn encryption_oracle() {
        // Crafted plaintext
        let plaintext = [0u8; 64].to_vec();

        for _ in 0..10 {
            let ciphertext = random_encrypt_aes_128(&plaintext, EncryptAes128Mode::Ecb);
            assert_eq!(is_encryption_mode_ecb(&ciphertext), true);
        }

        for _ in 0..10 {
            let ciphertext = random_encrypt_aes_128(&plaintext, EncryptAes128Mode::Cbc);
            assert_eq!(is_encryption_mode_ecb(&ciphertext), false);
        }

        for _ in 0..10 {
            let ciphertext = random_encrypt_aes_128(&plaintext, EncryptAes128Mode::Random);
            println!(
                "Encryption mode: {}",
                if is_encryption_mode_ecb(&ciphertext) {
                    "ECB"
                } else {
                    "CBC"
                }
            )
        }
    }
}
