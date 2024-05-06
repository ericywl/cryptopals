use base64::{prelude::BASE64_STANDARD, Engine};
use hex::FromHexError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum HexToBase64Error {
    #[error(transparent)]
    FromHex(#[from] FromHexError),
}

pub fn hex_to_base64(s: &str) -> Result<String, HexToBase64Error> {
    let bytes = hex::decode(s)?;
    Ok(BASE64_STANDARD.encode(bytes))
}

#[derive(Debug, PartialEq, Error)]
pub enum FixedXorError {
    #[error("Length mismatch")]
    LengthMismatch,
}

pub fn fixed_xor(lhs: &[u8], rhs: &[u8]) -> Result<Vec<u8>, FixedXorError> {
    if lhs.len() != rhs.len() {
        return Err(FixedXorError::LengthMismatch);
    }

    let mut v = lhs.to_vec();
    v.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x ^= *y);
    Ok(v)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn hex_to_base64_ok() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(hex_to_base64(input).unwrap(), expected)
    }

    #[test]
    fn fixed_xor_ok() {
        let lhs = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let rhs = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(fixed_xor(&lhs, &rhs).unwrap(), expected)
    }
}
