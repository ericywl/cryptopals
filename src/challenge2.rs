use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum FixedXorError {
    #[error("Length mismatch")]
    LengthMismatch,
}

/// XOR each byte of both inputs together.
/// Returns FixedXorError::LengthMismatch if both inputs don't have the same length.
pub fn fixed_xor(lhs: &[u8], rhs: &[u8]) -> Result<Vec<u8>, FixedXorError> {
    if lhs.len() != rhs.len() {
        return Err(FixedXorError::LengthMismatch);
    }

    let mut v = lhs.to_vec();
    v.iter_mut().zip(rhs.iter()).for_each(|(x, y)| *x ^= *y);
    Ok(v)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fixed_xor_ok() {
        let lhs = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let rhs = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(fixed_xor(&lhs, &rhs).unwrap(), expected)
    }
}
