use std::collections::HashMap;

use rand::{Rng, RngCore};

use crate::{encrypt_aes_128_cbc_with_pkcs7, encrypt_aes_128_ecb_with_pkcs7};

pub fn random_aes_128_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub enum EncryptAes128Mode {
    Random,
    Ecb,
    Cbc,
}

/// If mode is random, randomly selects between AES-128-CBC or AES-128-CBC to perform the encryption.
/// Otherwise, use the mode specified.
pub fn oracle_encrypt_aes_128(
    key: &[u8; 16],
    plaintext: &[u8],
    mode: EncryptAes128Mode,
) -> Vec<u8> {
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

/// Checks if the ciphertext is encrypted by AES-128-ECB
pub fn is_encryption_oracle_ecb<F>(oracle: F) -> bool
where
    F: Fn(&[u8]) -> Vec<u8>,
{
    // Crafted plaintext
    let plaintext = [42u8; 64].to_vec();

    let ciphertext = oracle(&plaintext);
    let mut set = HashMap::new();
    for chunk in ciphertext.chunks_exact(16) {
        if set.contains_key(chunk) {
            return true;
        }

        set.insert(chunk, true);
    }

    false
}

#[cfg(test)]
mod test {
    use rand::distributions::uniform::SampleRange;

    use super::*;

    fn random_bytes<R>(range: R) -> Vec<u8>
    where
        R: SampleRange<usize>,
    {
        let mut rng = rand::thread_rng();
        let bytes = rng.gen::<[u8; 32]>();
        let num = rng.gen_range(range);

        bytes[..num].to_vec()
    }

    fn random_pad<R>(buf: &[u8], range: R) -> Vec<u8>
    where
        R: SampleRange<usize> + Clone,
    {
        let mut result = random_bytes(range.clone());
        result.append(&mut buf.to_vec());
        result.append(&mut random_bytes(range));
        result
    }

    /// Runs `oracle_encrypt_aes_128` but the key is randomly generated and plaintext padded
    /// with 5-10 random bytes on both sides.
    fn oracle_encrypt_aes_128_with_random_key_and_pad(
        plaintext: &[u8],
        mode: EncryptAes128Mode,
    ) -> Vec<u8> {
        let plaintext = random_pad(plaintext, 5..=10);
        let key = random_aes_128_key();
        oracle_encrypt_aes_128(&key, &plaintext, mode)
    }

    #[test]
    fn encryption_oracle() {
        for _ in 0..10 {
            assert_eq!(
                is_encryption_oracle_ecb(|plaintext| {
                    oracle_encrypt_aes_128_with_random_key_and_pad(
                        &plaintext,
                        EncryptAes128Mode::Ecb,
                    )
                }),
                true
            );
        }

        for _ in 0..10 {
            assert_eq!(
                is_encryption_oracle_ecb(|plaintext| {
                    oracle_encrypt_aes_128_with_random_key_and_pad(
                        &plaintext,
                        EncryptAes128Mode::Cbc,
                    )
                }),
                false
            );
        }

        for _ in 0..10 {
            let is_ecb = is_encryption_oracle_ecb(|plaintext| {
                oracle_encrypt_aes_128_with_random_key_and_pad(
                    &plaintext,
                    EncryptAes128Mode::Random,
                )
            });
            println!("Encryption mode: {}", if is_ecb { "ECB" } else { "CBC" })
        }
    }
}
