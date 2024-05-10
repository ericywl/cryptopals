use super::fixed_xor;

/// Repeat the key until it reaches provided length.
/// For example, `("abc", 10)` will output `"abcabcabca"`.
fn repeat_key_until(key: &[u8], len: usize) -> Vec<u8> {
    if key.len() > len {
        key[..len].to_vec()
    } else {
        key.repeat((len / key.len()) + 1)[..len].to_vec()
    }
}

/// XOR each byte of the left hand side input with one byte in the key sequentially.
/// For example, if `lhs = "ABCDEFG"` and `key = "123"`,
/// `A` will be XOR'd with `1`, `B` with `2`, `C` with `3`, `D` with `1`, `E` with `2` and so on.
pub fn repeating_key_xor(lhs: &[u8], key: &[u8]) -> Vec<u8> {
    // Unwrap since it will be same length
    fixed_xor(lhs, &repeat_key_until(key, lhs.len())).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn repeat_key_until_ok() {
        let repeated = repeat_key_until("abc".as_bytes(), 10);
        assert_eq!(repeated, "abcabcabca".as_bytes())
    }

    #[test]
    fn repeating_key_xor_ok() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            .as_bytes();

        let result = repeating_key_xor(input, "ICE".as_bytes());
        assert_eq!(
            hex::encode(result),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
