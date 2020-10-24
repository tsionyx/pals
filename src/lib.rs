#![allow(clippy::must_use_candidate)]

use std::iter;

use itertools::Itertools;

pub mod freq;

pub trait StreamCipher {
    fn xor<I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = u8> + Clone;
}

fn xor_internal<'a, T, I>(plain: T, key: I) -> Vec<u8>
where
    T: Iterator<Item = &'a u8>,
    I: Iterator<Item = u8> + Clone,
{
    plain
        .zip(key.cycle())
        .map(|(plain_byte, key_byte)| plain_byte ^ key_byte)
        .collect()
}

impl StreamCipher for str {
    fn xor<I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = u8> + Clone,
    {
        self.as_bytes().xor(key)
    }
}

impl StreamCipher for [u8] {
    fn xor<I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = u8> + Clone,
    {
        xor_internal(self.iter(), key)
    }
}

pub trait StrCryptoExt {
    fn parse_hex(&self) -> Vec<u8>;
    fn is_printable_ascii(&self) -> bool;
}

impl StrCryptoExt for str {
    /// <https://codereview.stackexchange.com/a/201699>
    fn parse_hex(&self) -> Vec<u8> {
        let hex_bytes = self
            .as_bytes()
            .iter()
            .filter_map(|b| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            })
            .fuse();

        hex_bytes.tuples().map(|(h, l)| h << 4 | l).collect()
    }

    fn is_printable_ascii(&self) -> bool {
        self.chars()
            .all(|ch| ch.is_ascii_whitespace() || !ch.is_ascii_control())
    }
}

/// Higher score signifies the text is going further away from
/// the standard english text (in terms of letter's frequencies
fn english_text_score(text: &str) -> u64 {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]

    let standard = freq::eng_map();
    let real = freq::letters_frequencies(text);
    let score: f64 = standard
        .into_iter()
        .map(|(ch, std_freq)| {
            real.get(&ch).map_or(1.0, |freq| {
                // the close to standard, the lower the score
                (std_freq - freq).abs()
            })
        })
        .sum();

    let punctuation = text.chars().filter(char::is_ascii_punctuation).count();

    // every punctuation sign adds a bit to the artificiality of the text
    let punctuation_score = (punctuation as f64) * 0.2;
    let score = score + punctuation_score;

    (score * 1000.0) as u64
}

pub trait HexDisplay {
    fn as_hex(&self) -> String;
}

impl HexDisplay for [u8] {
    fn as_hex(&self) -> String {
        self.iter().map(|x| format!("{:x}", x)).collect()
    }
}

pub trait BytesCryptoExt {
    fn guess_the_single_char_xor_key(&self) -> Vec<(u8, String, u64)>;

    /// Find the most suitable single character (u8) that,
    /// xor-ed to the given text produce a valid ASCII printable text
    /// statistically closed to english text.
    ///
    /// # Errors
    /// - every character we try, produces bad string (not a valid UTF-8) when xor-ed
    /// - every character we try, produces non-printable ASCII symbols
    fn find_key_char(&self) -> Result<u8, String>;
}

impl BytesCryptoExt for Vec<u8> {
    #![allow(clippy::use_self)]

    fn guess_the_single_char_xor_key(&self) -> Vec<(u8, String, u64)> {
        // eprintln!("{:x?}", self);

        let keys_space = 0..=u8::MAX;
        let mut candidates: Vec<_> = keys_space
            .filter_map(|key| {
                let raw = self.xor(iter::once(key));
                String::from_utf8(raw).ok().map(|plain| {
                    let score = english_text_score(&plain);
                    (key, plain, score)
                })
            })
            .collect();

        candidates.sort_unstable_by_key(|(_key, _plain, score)| *score);

        // print the top candidates for debug
        let debug_top_candidates = candidates.len().min(10);
        for (key, plain, score) in &candidates[..debug_top_candidates] {
            eprintln!("{} ({}). {} -> {}", key, *key as char, plain, score);
        }

        candidates
    }

    /// Find the most suitable single character (u8) that,
    /// xor-ed to the given text produce a valid ASCII printable text
    /// statistically closed to english text.
    ///
    /// # Errors
    /// - every character we try, produces bad string (not a valid UTF-8) when xor-ed
    /// - every character we try, produces non-printable ASCII symbols
    fn find_key_char(&self) -> Result<u8, String> {
        let candidates = self.guess_the_single_char_xor_key();
        if candidates.is_empty() {
            return Err("No valid key char can be found".to_string());
        }

        eprintln!(
            "Trying to decrypt the line {:?} with single character",
            self
        );

        for (key, plain, score) in &candidates {
            // unprintable non-whitespace symbol
            if !plain.is_printable_ascii() {
                continue;
            }

            eprintln!(
                "The key is {}({:?}). Plaintext is: {:?} (score={})",
                key, *key as char, plain, score
            );

            return Ok(*key);
        }

        Err("All the sequences has bad characters".to_string())
    }
}

pub fn hamming(lhs: impl AsRef<[u8]>, rhs: impl AsRef<[u8]>) -> u32 {
    lhs.as_ref()
        .iter()
        .zip(rhs.as_ref())
        .map(|(l, r)| (l ^ r).count_ones())
        .sum()
}

pub mod aes_cypher {
    use aes::{cipher::generic_array::GenericArray, Aes128, BlockCipher, NewBlockCipher};

    macro_rules! enc_dec {
        ($func_name:ident, $direction:ident) => {
            pub fn $func_name<'a, 'b>(
                data: &'a [u8],
                key: &'b [u8],
            ) -> impl Iterator<Item = Vec<u8>> + 'a {
                let key = GenericArray::from_slice(key);
                let cipher = Aes128::new(key);

                data.chunks(16).map(move |block| {
                    let mut block = GenericArray::clone_from_slice(block);
                    cipher.$direction(&mut block);
                    block.to_vec()
                })
            }
        };
    }

    enc_dec!(encrypt, encrypt_block);
    enc_dec!(decrypt, decrypt_block);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity() {
        let a = "this is a test";
        let b = "wokka wokka!!!";

        assert_eq!(hamming(a, b), 37);
    }
}
