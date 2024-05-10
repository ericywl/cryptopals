pub fn pkcs7_padding(plaintext: &[u8], block_size: usize) -> Vec<u8> {
    let num_padding = block_size - (plaintext.len() % block_size);
    let mut result = plaintext.to_vec();
    result.append(&mut [num_padding as u8].repeat(num_padding).to_vec());
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pkcs7_padding_ok() {
        let plaintext = pkcs7_padding("YELLOW SUBMARINE".as_bytes(), 20);
        assert_eq!(plaintext, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes())
    }
}
