use std::{
    fmt::Display,
    fs::File,
    io::{self, BufRead, BufReader},
};

use base64::{prelude::BASE64_STANDARD, Engine};
use hex::FromHexError;
use thiserror::Error;

/// Converts string representation from hexadecimal to base64.
/// Returns FromHexError if there was some issue decoding the hexadecimal string.
pub fn hex_to_base64(s: &str) -> Result<String, FromHexError> {
    let bytes = hex::decode(s)?;
    Ok(BASE64_STANDARD.encode(bytes))
}

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

/// XOR each byte of the left hand side input with a single byte.
pub fn single_byte_xor(lhs: &[u8], single: u8) -> Vec<u8> {
    let rhs = [single].repeat(lhs.len());
    // Unwrap since it will never have length mismatch error
    fixed_xor(lhs, &rhs).unwrap()
}

/// Calculate the character frequencies of the input.
pub fn calculate_char_frequencies(buf: &[u8]) -> [usize; 256] {
    let mut frequencies: [usize; 256] = [0; 256];
    for b in buf {
        frequencies[b.to_owned() as usize] += 1
    }

    frequencies
}

/// Assign a score to each char based on relative frequency.
/// Higher frequency = higher score.
/// Sourced from: https://en.wikipedia.org/wiki/Letter_frequency.
fn char_score(c: char) -> f64 {
    match c.to_ascii_lowercase() {
        ' ' => 21.3,
        'e' => 12.7,
        't' => 9.1,
        'a' => 8.2,
        'o' => 7.5,
        'i' => 7.,
        'n' => 6.7,
        's' => 6.3,
        'h' => 6.1,
        'r' => 6.,
        'd' => 4.3,
        'l' => 4.,
        'c' => 2.8,
        'u' => 2.8,
        'm' => 2.4,
        'w' => 2.4,
        'f' => 2.2,
        'g' => 2.,
        'y' => 2.,
        'p' => 1.9,
        'b' => 1.5,
        'v' => 0.98,
        'k' => 0.77,
        'j' => 0.15,
        'x' => 0.15,
        'q' => 0.095,
        'z' => 0.074,
        _ => 0.,
    }
}

/// Assign a relative frequency score to the input.
/// The score is calculated by sum of all characters' `frequency * char_score()`.
pub fn calculate_relative_frequency_score(input: &[u8]) -> f64 {
    let frequencies = calculate_char_frequencies(input);
    frequencies
        .iter()
        .enumerate()
        .map(|(i, f)| (f.to_owned() as f64) * char_score(i as u8 as char))
        .sum()
}

#[derive(Debug, PartialEq, Clone)]
pub struct Guess {
    pub byte: u8,
    pub score: f64,
    pub output: Vec<u8>,
}

impl Guess {
    pub fn empty() -> Self {
        Self {
            byte: 0,
            score: 0.,
            output: Vec::new(),
        }
    }
}

impl Display for Guess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Guess: {}\nScore: {:.2}\nOutput: {}",
            self.byte as char,
            self.score,
            String::from_utf8(self.output.clone()).unwrap(),
        )
    }
}

/// Provides a best guess to what the single byte XOR might be for the input.
/// Returns the guess byte, score and output i.e. input XOR'd with the guess byte.
pub fn guess_single_byte_xor(input: &[u8]) -> Guess {
    let mut guess_byte = 0;
    let mut highest_score = 0.0;

    for i in 0..255 {
        let xor_result = single_byte_xor(input, i);
        let score = calculate_relative_frequency_score(&xor_result);
        if score > highest_score {
            highest_score = score;
            guess_byte = i;
        }
    }

    Guess {
        byte: guess_byte,
        score: highest_score,
        output: single_byte_xor(input, guess_byte),
    }
}

#[derive(Debug, Error)]
pub enum DetectSingleByteXorError {
    #[error(transparent)]
    FromHex(#[from] FromHexError),

    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Tries to detect if there is any single byte XOR in a file full of hexadecimal strings.
/// Returns a guess of the line that was most likely to be single byte XOR'd.
pub fn detect_single_byte_xor_in_file(path: &str) -> Result<Guess, DetectSingleByteXorError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut best_guess = Guess::empty();

    for line in reader.lines() {
        let input = hex::decode(line?)?;
        let guess = guess_single_byte_xor(&input);
        if guess.score > best_guess.score {
            best_guess = guess;
        }
    }

    Ok(best_guess)
}

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
    fixed_xor(lhs, &repeat_key_until(key, lhs.len())).unwrap()
}

/// Compute the hamming distance between two byte arrays.
pub fn compute_hamming_distance(lhs: &[u8], rhs: &[u8]) -> Result<usize, FixedXorError> {
    let result = fixed_xor(lhs, rhs)?;
    Ok(result.iter().map(|b| b.count_ones()).sum::<u32>() as usize)
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

    #[test]
    fn calculate_char_frequencies_ok() {
        let input = "hello this is a game";
        let frequencies = calculate_char_frequencies(input.as_bytes());

        assert_eq!(frequencies[' ' as usize], 4);
        assert_eq!(frequencies['h' as usize], 2);
        assert_eq!(frequencies['e' as usize], 2);
        assert_eq!(frequencies['l' as usize], 2);
        assert_eq!(frequencies['o' as usize], 1);
        assert_eq!(frequencies['t' as usize], 1);
        assert_eq!(frequencies['i' as usize], 2);
    }

    #[test]
    fn guess_single_byte_xor_ok() {
        let input =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();

        let guess = guess_single_byte_xor(&input);
        assert_eq!(guess.byte as char, 'X');
        assert_eq!(
            String::from_utf8(guess.output).unwrap(),
            "Cooking MC's like a pound of bacon"
        );
    }

    #[test]
    fn detect_single_byte_xor_in_file_ok() {
        let guess = detect_single_byte_xor_in_file("test.txt").expect("Unexpected error");
        assert_eq!(guess.byte as char, '5');
        assert_eq!(
            String::from_utf8(guess.output).unwrap(),
            "Now that the party is jumping\n"
        );
    }

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
