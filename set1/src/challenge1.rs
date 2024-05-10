use base64::{self, prelude::BASE64_STANDARD, Engine};

/// Converts string representation from hexadecimal to base64.
/// Returns FromHexError if there was some issue decoding the hexadecimal string.
pub fn hex_to_base64(s: &str) -> Result<String, hex::FromHexError> {
    let bytes = decode_hex(s)?;
    Ok(encode_base64(&bytes))
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

pub fn encode_hex(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn decode_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    BASE64_STANDARD.decode(s)
}

pub fn encode_base64(b: &[u8]) -> String {
    BASE64_STANDARD.encode(b)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hex_to_base64_ok() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(hex_to_base64(input).unwrap(), expected)
    }
}
