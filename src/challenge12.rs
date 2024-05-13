use std::collections::HashMap;
use std::sync::OnceLock;

use super::{
    is_encryption_oracle_ecb, oracle_encrypt_aes_128, random_aes_128_key, EncryptAes128Mode,
};

/// Generate a random key once and always return the same randomized key after the first call.
fn fixed_random_key() -> [u8; 16] {
    // A `static` value is shared and reused whenever you call the
    // function, and this `OnceLock::new()` will only be called once,
    // when the program starts.
    static KEY: OnceLock<[u8; 16]> = OnceLock::new();

    // `OnceLock::get_or_init` is designed to be called only once,
    // when you reach this line for the first time.
    *KEY.get_or_init(random_aes_128_key)
}

/// Encrypt AES-128 using a fixed random key.
pub fn oracle_encrypt_aes_128_with_fixed_random_key(
    plaintext: &[u8],
    mode: EncryptAes128Mode,
) -> Vec<u8> {
    let key = fixed_random_key();
    oracle_encrypt_aes_128(&key, &plaintext, mode)
}

/// Try to detect ECB block size, where the `max_byte_size` is the maximum block size search space.
///
/// # Returns
///
/// - `None` if the cipher function is not ECB or if the block size still cannot be found after
///     finished iterating `max_byte_size`.
/// - `Some(usize)` if the ECB block size is found.
pub fn check_ecb_block_size<F>(oracle: F, max_byte_size: usize) -> Option<usize>
where
    F: Fn(&[u8]) -> Vec<u8> + Clone,
{
    if !is_encryption_oracle_ecb(oracle.clone()) {
        return None;
    }

    for i in 1..=max_byte_size {
        let plaintext1 = [0u8].repeat(i);
        let plaintext2 = [0u8].repeat(i + 1);

        let ciphertext1 = oracle(&plaintext1);
        let ciphertext2 = oracle(&plaintext2);

        if ciphertext1[..i] == ciphertext2[..i] {
            return Some(i);
        }
    }

    None
}

// Get the last block of the buffer.
// If buffer size is less than specified block size, returns block with all zeroes.
fn get_last_block_or_empty(buf: &[u8], block_size: usize) -> Vec<u8> {
    if buf.len() < block_size {
        [0u8].repeat(block_size)
    } else {
        buf[buf.len() - block_size..].to_vec()
    }
}

/// Generate lookup table of encrypted block to byte.
fn generate_byte_lookup_table<F>(oracle: F, working_block: &[u8]) -> HashMap<Vec<u8>, u8>
where
    F: Fn(&[u8]) -> Vec<u8> + Copy,
{
    let len = working_block.len();
    let mut block = working_block.to_owned();
    block.rotate_left(1);

    // Build map of encrypted block to byte.
    let mut lookup_table = HashMap::new();
    for b in 0..=255u8 {
        block[len - 1] = b;

        let ciphertext = oracle(&block);
        // We only care about the block that we crafted i.e. the first block.
        let ciphertext_block = ciphertext[..len].to_owned();
        lookup_table.insert(ciphertext_block, b);
    }

    lookup_table
}

// Crack AES-ECB oracle suffix.
//
// The oracle behaves as such given plaintext:
//  1. Add a suffix to the plaintext
//  2. Pad the plaintext with PKCS#7 padding
//  3. Encrypt the plaintext with some sort of AES-ECB
//  4. Returns the ciphertext
//
// The objective is to retrieve the suffix by analyzing the oracle.
pub fn crack_aes_128_ecb_oracle_suffix<F>(oracle: F) -> Vec<u8>
where
    F: Fn(&[u8]) -> Vec<u8> + Copy,
{
    let mut suffix = Vec::new();
    let block_size = check_ecb_block_size(oracle, 64).unwrap();
    let num_blocks = oracle(&[]).len() / block_size;

    for block_num in 0..num_blocks {
        // If block size was 8, the below would look like this at the start
        // `[0, 0, 0, 0, 0, 0, 0, 0]`
        let mut curr_suffix_block = get_last_block_or_empty(&suffix, block_size);

        // We loop through from 1 to block size and try to figure out what's the suffix byte
        // at index `i`.
        //
        // Once we figure out, we add the byte on the plaintext block above and rotate left.
        // For example, let's say the suffix block is `[s, e, c, r, e, t, a, b]` (in bytes).
        //
        // First iteration:  `[0, 0, 0, 0, 0, 0, 0, s]`
        // Second iteration: `[0, 0, 0, 0, 0, 0, s, e]`
        // Third iteration:  `[0, 0, 0, 0, 0, s, e, c]`
        // ...
        // Final iteration:  `[s, e, c, r, e, t, a, b]`
        for i in 1..=block_size {
            // Build a byte lookup table.
            //
            // Based on the example above, on the third iteration, we will build a map that
            // contains 256 entries with...
            //  - key:   encrypted version of `[0, 0, 0, 0, s, e, c, *]`, where `*` is any of 256 bytes,
            //  - value: the byte in `*` above.
            let lookup_table = generate_byte_lookup_table(oracle.clone(), &curr_suffix_block);

            // Now that we have the map, we can try to discover the new byte.
            //
            // On third iteration, we know that the suffix block looks like `[s, e, c, *, -, -, -, -]`
            // where `*` is the byte we are trying to find.
            // We add padding `[0, 0, 0, 0]` so that `*` is on the last slot, e.g. `[0, 0, 0, 0, s, e, c, *]`
            // when the block is getting encrypted.
            //
            // After encryption, we cross reference it with the lookup table that we built previously to
            // find the byte we are looking for.
            let ciphertext = oracle(&[0u8].repeat(block_size - i));
            let ciphertext_block =
                ciphertext[block_size * block_num..block_size * (block_num + 1)].to_owned();
            let potential_byte = lookup_table.get(&ciphertext_block);

            // If it is the last block and we cannot find the byte and the previous byte was 0x1,
            // it means that we have exhausted the search, simply return
            //
            // Reason for 0x1 is because that is the PKCS7 padding that results from us trying
            // to find a byte that doesn't exist.
            //
            // Consider the suffix of `yes` with block size 8, when we reach the end, the oracle
            // will be encrypting `[0, 0, 0, 0, y, e, s, 0x1]` because it will be padded before encryption.
            // This will always succeed because we consider all 256 values in trying to search the byte.
            // However, in the next iteration, the oracle will be encrypting `[0, 0, 0, y, e, s, 0x2, 0x2]`
            // and our previously discovered `0x1` is no longer correct, and hence will result in an empty
            // potential byte.
            if block_num == num_blocks - 1
                && potential_byte.is_none()
                && curr_suffix_block[block_size - 1] == 0x1
            {
                curr_suffix_block = curr_suffix_block[block_size - i + 1..block_size - 1].to_vec();
                break;
            }

            // Move the bytes over to the left by 1, to make space for the new byte we are going
            // to discover.
            curr_suffix_block.rotate_left(1);
            // Assign the new byte.
            curr_suffix_block[block_size - 1] = potential_byte.unwrap().to_owned();
        }

        suffix.append(&mut curr_suffix_block.clone());
    }

    suffix
}

#[cfg(test)]
mod test {
    use super::super::decode_base64;
    use super::*;

    const SUFFIX_B64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    #[test]
    fn check_ecb_block_size_ok() {
        // Correct
        let ecb_block_size = check_ecb_block_size(
            |plaintext| {
                oracle_encrypt_aes_128_with_fixed_random_key(plaintext, EncryptAes128Mode::Ecb)
            },
            64,
        );
        assert_eq!(ecb_block_size.unwrap(), 16);

        // Low max byte size
        let ecb_block_size = check_ecb_block_size(
            |plaintext| {
                oracle_encrypt_aes_128_with_fixed_random_key(plaintext, EncryptAes128Mode::Ecb)
            },
            12,
        );
        assert!(ecb_block_size.is_none());

        // CBC
        let ecb_block_size = check_ecb_block_size(
            |plaintext| {
                oracle_encrypt_aes_128_with_fixed_random_key(plaintext, EncryptAes128Mode::Cbc)
            },
            64,
        );
        assert!(ecb_block_size.is_none());
    }

    #[test]
    fn crack_aes_128_ecb_oracle_suffix_ok() {
        let ecb_oracle = |plaintext: &[u8]| -> Vec<u8> {
            let mut plaintext = plaintext.to_vec();
            let mut suffix = decode_base64(SUFFIX_B64).unwrap();
            plaintext.append(&mut suffix);

            oracle_encrypt_aes_128_with_fixed_random_key(&plaintext, EncryptAes128Mode::Ecb)
        };

        let suffix = crack_aes_128_ecb_oracle_suffix(ecb_oracle);
        assert_eq!(suffix, decode_base64(SUFFIX_B64).unwrap());
    }
}
