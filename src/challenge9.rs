use thiserror::Error;

/// Adds PKCS#7 padding to the bytes.
pub fn pkcs7_padding(buf: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block_size - (buf.len() % block_size);
    let mut result = buf.to_vec();
    result.append(&mut [padding as u8].repeat(padding).to_vec());
    result
}

#[derive(Debug, Error)]
pub enum Pkcs7PaddingError {
    #[error("Invalid padding")]
    InvalidPadding,
}

/// Removes PKCS#7 padding from the bytes.
/// If supposed padding is larger than block size, return error.
pub fn remove_pkcs7_padding(buf: &[u8], block_size: usize) -> Result<Vec<u8>, Pkcs7PaddingError> {
    let padding = buf[buf.len() - 1] as usize;
    if padding > block_size {
        Err(Pkcs7PaddingError::InvalidPadding)
    } else {
        Ok(buf[..buf.len() - padding].to_vec())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pkcs7_padding_ok() {
        let block_size = 20;
        let original_text = "YELLOW SUBMARINE".to_owned();
        let padded = pkcs7_padding(original_text.clone().as_bytes(), block_size);
        assert_eq!(
            padded,
            (original_text.clone() + "\x04\x04\x04\x04").as_bytes()
        );

        let plaintext = remove_pkcs7_padding(&padded, block_size).unwrap();
        assert_eq!(plaintext, original_text.as_bytes());
    }
}
