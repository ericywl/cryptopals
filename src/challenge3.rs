use std::fmt::Display;

use super::fixed_xor;

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
pub struct SingleByteXorGuess {
    pub key: u8,
    pub score: f64,
    pub output: Vec<u8>,
}

impl SingleByteXorGuess {
    pub fn empty() -> Self {
        Self {
            key: 0,
            score: 0.,
            output: Vec::new(),
        }
    }
}

impl Display for SingleByteXorGuess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Guess: {}\nScore: {:.2}\nOutput: {}",
            self.key as char,
            self.score,
            String::from_utf8(self.output.clone()).unwrap(),
        )
    }
}

/// Provides a best guess to what the single byte XOR might be for the input.
/// Returns the guess byte, score and output i.e. input XOR'd with the guess byte.
pub fn guess_single_byte_xor_key(input: &[u8]) -> SingleByteXorGuess {
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

    SingleByteXorGuess {
        key: guess_byte,
        score: highest_score,
        output: single_byte_xor(input, guess_byte),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let guess = guess_single_byte_xor_key(&input);
        assert_eq!(guess.key as char, 'X');
        assert_eq!(
            guess.output,
            "Cooking MC's like a pound of bacon".as_bytes()
        );
    }
}
