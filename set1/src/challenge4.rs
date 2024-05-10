use std::io::{self, BufRead};

use thiserror::Error;

use super::{guess_single_byte_xor_key, SingleByteXorGuess};

#[derive(Debug, Error)]
pub enum DetectSingleByteXorError {
    #[error("Empty input")]
    EmptyInput,

    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),

    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Tries to detect if there is any single byte XOR in the input that is full of hexadecimal strings.
/// Returns a guess of the line that was most likely to be single byte XOR'd.
pub fn detect_single_byte_xor(
    input: impl io::Read,
) -> Result<SingleByteXorGuess, DetectSingleByteXorError> {
    let reader = io::BufReader::new(input);
    let mut best_guess: Option<SingleByteXorGuess> = None;

    for line in reader.lines() {
        let input = hex::decode(line?)?;
        let guess = guess_single_byte_xor_key(&input);
        if best_guess.is_none() || guess.score > best_guess.clone().unwrap().score {
            best_guess = Some(guess);
        }
    }

    // Return guess or error if empty guess
    if best_guess.is_some() {
        Ok(best_guess.unwrap())
    } else {
        Err(DetectSingleByteXorError::EmptyInput)
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;

    use super::*;

    #[test]
    fn detect_single_byte_xor_ok() {
        let file = File::open("data/test_single_byte_xor.txt").expect("Cannot open file");
        let guess = detect_single_byte_xor(file).expect("Unexpected error");
        assert_eq!(guess.key as char, '5');
        assert_eq!(guess.output, "Now that the party is jumping\n".as_bytes());
    }
}
