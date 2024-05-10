use std::{
    fs::File,
    io::{self, BufRead},
};

use thiserror::Error;

use super::{decode_base64, fixed_xor, guess_single_byte_xor_key, FixedXorError};

/// Compute the hamming distance between two byte arrays.
/// The byte arrays have to be equal length.
fn compute_hamming_distance(lhs: &[u8], rhs: &[u8]) -> Result<usize, FixedXorError> {
    let result = fixed_xor(lhs, rhs)?;
    Ok(result.iter().map(|b| b.count_ones()).sum::<u32>() as usize)
}

/// Compute the hamming distance between two byte arrays, normalized by the length of the byte array.
/// The byte arrays have to be equal length.
fn compute_normalized_hamming_distance(lhs: &[u8], rhs: &[u8]) -> Result<f64, FixedXorError> {
    let result = compute_hamming_distance(lhs, rhs)?;
    Ok(result as f64 / lhs.len() as f64)
}

/// Compute the normalized hamming distance for each combination of inputs and average them.
/// The byte arrays have to be equal length.
fn compute_average_normalized_hamming_distance(inputs: &[&[u8]]) -> Result<f64, FixedXorError> {
    let mut ops = 0.;
    let mut sum = 0.;

    for i in 0..inputs.len() {
        for j in (i + 1)..inputs.len() {
            let distance = compute_normalized_hamming_distance(inputs[i], inputs[j])?;
            sum += distance;
            ops += 1.;
        }
    }

    Ok(sum / ops)
}

#[derive(Debug, Error)]
pub enum CrackRepeatingKeyXorError {
    #[error("Empty input")]
    EmptyInput,

    #[error("Line exceeds twice of max key size")]
    LineExceedsMaxSize,

    #[error(transparent)]
    FixedXor(#[from] FixedXorError),

    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Guess the key size used for repeating key XOR on the input.
/// The `max_key_size` represents the maximum search space for the key size.
fn guess_repeating_key_xor_key_size(
    line: &[u8],
    max_key_size: usize,
) -> Result<usize, CrackRepeatingKeyXorError> {
    if max_key_size * 4 > line.len() {
        return Err(CrackRepeatingKeyXorError::LineExceedsMaxSize);
    }

    let mut best_key_size = 1;
    let mut smallest_normalized_distance = f64::MAX;

    for key_size in 2..=max_key_size {
        let parts = [
            &line[..key_size],
            &line[key_size..key_size * 2],
            &line[key_size * 2..key_size * 3],
            &line[key_size * 3..key_size * 4],
        ];

        let normalized_distance = compute_average_normalized_hamming_distance(&parts)?;
        if normalized_distance < smallest_normalized_distance {
            smallest_normalized_distance = normalized_distance;
            best_key_size = key_size;
        }
    }

    Ok(best_key_size)
}

/// Transpose transposes the matrix.
/// For example, `[[1, 2, 3], [4, 5, 6]]` will turn into `[[1, 4], [2, 5], [3, 6]]`.
pub fn transpose<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    if v.is_empty() {
        return v;
    }

    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();

    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}

/// Guess the key used for repeating key XOR on the input.
/// The `max_key_size` represents the maximum search space for the key size.
pub fn guess_repeating_key_xor_key(
    buf: &[u8],
    max_key_size: usize,
) -> Result<Vec<u8>, CrackRepeatingKeyXorError> {
    // Guess the key size
    let key_size = guess_repeating_key_xor_key_size(&buf, max_key_size)?;

    // Split buffer into chunks of key size, and transpose them.
    let chunks = transpose(
        buf.chunks_exact(key_size)
            .map(|chunk| chunk.to_vec())
            .collect(),
    );

    // For each chunk, guess the single byte XOR and collect them
    let key: Vec<_> = chunks
        .iter()
        .map(|chunk| guess_single_byte_xor_key(chunk).key)
        .collect();
    Ok(key)
}

/// Reads from input, ignoring newline character.
fn read_string_ignoring_newline(input: impl io::Read) -> Result<String, io::Error> {
    let reader = io::BufReader::new(input);

    let mut read_str = String::new();
    for line_result in reader.lines() {
        let line = line_result?;
        read_str = read_str + &line.replace("\n", "");
    }

    Ok(read_str)
}

#[derive(Debug, Error)]
pub enum DecodeBase64FromFileError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),
}

pub fn decode_base64_from_file(path: &str) -> Result<Vec<u8>, DecodeBase64FromFileError> {
    let file = File::open(path)?;
    let read_str = read_string_ignoring_newline(file)?;

    let result = decode_base64(&read_str)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::repeating_key_xor;
    use super::*;

    #[test]
    fn compute_hamming_distance_ok() {
        let lhs = "this is a test".as_bytes();
        let rhs = "wokka wokka!!!".as_bytes();

        let distance = compute_hamming_distance(lhs, rhs).expect("Unexpected error");
        assert_eq!(distance, 37);
    }

    #[test]
    fn guess_repeating_key_xor_key_size_ok() {
        let buf = decode_base64_from_file("data/challenge6.txt").expect("Unexpected error");

        let key_size = guess_repeating_key_xor_key_size(&buf, 40).expect("Unexpected error");
        assert_eq!(key_size, 29);
    }

    #[test]
    fn transpose_ok() {
        let input = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let transposed = transpose(input);
        assert_eq!(transposed, vec![vec![1, 4], vec![2, 5], vec![3, 6]]);
    }

    #[test]
    fn guess_repeating_key_xor_key_ok() {
        let buf = decode_base64_from_file("data/challenge6.txt").expect("Unexpected error");

        let key = guess_repeating_key_xor_key(&buf, 40).expect("Unexpected error");
        assert_eq!(key, "Terminator X: Bring the noise".as_bytes());

        let plaintext = repeating_key_xor(&buf, &key);
        let plaintext = String::from_utf8(plaintext).unwrap();

        println!("{plaintext}");
        assert!(plaintext.contains("Play that funky music"));
    }
}
