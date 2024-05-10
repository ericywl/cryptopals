use std::{
    collections::HashMap,
    io::{self, BufRead},
};

use thiserror::Error;

use super::decode_hex;

#[derive(Debug, Error)]
pub enum DetectAes128EcbError {
    #[error("Empty input")]
    EmptyInput,

    #[error(transparent)]
    FromHex(#[from] hex::FromHexError),

    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Tries to detect if there is a line in the input that has been encrypted by
/// AES-128-ECB, by detecting block duplication.
///
/// If no block duplication found in all lines, returns `Ok(None)`;
pub fn detect_aes_128_ecb(input: impl io::Read) -> Result<Option<Vec<u8>>, DetectAes128EcbError> {
    let reader = io::BufReader::new(input);

    let mut guess = (Vec::new(), 0);
    for line in reader.lines() {
        let line = decode_hex(&line?)?;
        let mut set = HashMap::new();

        line.chunks_exact(16)
            .for_each(|chunk| *set.entry(chunk).or_insert(0) += 1);

        let max_block_dups_in_line = set
            .iter()
            .max_by(|a, b| a.1.cmp(&b.1))
            .map(|(_, &num)| num)
            .ok_or(DetectAes128EcbError::EmptyInput)?;

        if max_block_dups_in_line > guess.1 {
            guess = (line.clone(), max_block_dups_in_line)
        }
    }

    if guess.1 == 0 {
        Ok(None)
    } else {
        Ok(Some(guess.0))
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;

    use super::super::encode_hex;
    use super::*;

    #[test]
    fn detect_aes_128_ecb_ok() {
        let file = File::open("data/challenge8.txt").expect("Cannot open file");
        let guess = detect_aes_128_ecb(file)
            .expect("Unexpected error")
            .expect("Should have guess");

        assert_eq!(encode_hex(&guess), "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
    }
}
