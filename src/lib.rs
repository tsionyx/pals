#![allow(clippy::must_use_candidate)]

use std::iter;

use itertools::Itertools;
use rand::Rng;

pub mod freq;

pub trait StreamCipher {
    fn xor<I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = u8> + Clone;

    fn xor_ref<'a, I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a u8> + Clone;
}

impl StreamCipher for str {
    fn xor<I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = u8> + Clone,
    {
        self.as_bytes().xor(key)
    }

    fn xor_ref<'a, I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a u8> + Clone,
    {
        self.as_bytes().xor_ref(key)
    }
}

impl StreamCipher for [u8] {
    fn xor<I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = u8> + Clone,
    {
        self.iter()
            .zip(key.cycle())
            .map(|(plain_byte, key_byte)| plain_byte ^ key_byte)
            .collect()
    }

    fn xor_ref<'a, I>(&self, key: I) -> Vec<u8>
    where
        I: Iterator<Item = &'a u8> + Clone,
    {
        self.iter()
            .zip(key.cycle())
            .map(|(plain_byte, key_byte)| plain_byte ^ key_byte)
            .collect()
    }
}

pub trait StrCryptoExt {
    fn parse_hex(&self) -> Vec<u8>;
    fn is_printable_ascii(&self) -> bool;
    fn strip_pkcs7_padding(&self, block_size: u8) -> Option<String>;
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

    fn strip_pkcs7_padding(&self, block_size: u8) -> Option<String> {
        let mut bytes: Vec<_> = self.bytes().collect();
        let _padding_size = bytes.pkcs7_padding_size(block_size)?;

        bytes.unpad_pkcs7(block_size);
        String::from_utf8(bytes).ok()
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

    fn pad_pkcs7(&mut self, block_size: u8);
    fn pkcs7_padding_size(&self, block_size: u8) -> Option<usize>;
    fn unpad_pkcs7(&mut self, block_size: u8);

    fn generate_random(count: usize) -> Self;
}

impl BytesCryptoExt for Vec<u8> {
    #![allow(clippy::use_self)]

    fn guess_the_single_char_xor_key(&self) -> Vec<(u8, String, u64)> {
        // eprintln!("{:x?}", self);

        let keys_space = 0..=std::u8::MAX;
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

    fn pad_pkcs7(&mut self, block_size: u8) {
        if block_size < 2 {
            return;
        }

        let block_size = block_size as usize;
        let to_pad = block_size - self.len() % block_size;

        #[allow(clippy::cast_possible_truncation)]
        let padding = iter::repeat(to_pad as u8).take(to_pad);
        self.extend(padding);
    }

    fn pkcs7_padding_size(&self, block_size: u8) -> Option<usize> {
        if self.is_empty() {
            return None;
        }

        if block_size < 1 {
            return None;
        }

        let last_byte = *self.last().unwrap();
        if last_byte > block_size {
            return None;
        }

        let unpad_bytes = last_byte as usize;
        let padding: Vec<_> = self.iter().rev().take(unpad_bytes).collect();
        if padding == vec![&last_byte; unpad_bytes] {
            return Some(unpad_bytes);
        }

        None
    }

    fn unpad_pkcs7(&mut self, block_size: u8) {
        if let Some(unpad_bytes) = self.pkcs7_padding_size(block_size) {
            self.truncate(self.len() - unpad_bytes);
        }
    }

    fn generate_random(count: usize) -> Self {
        let mut rng = rand::thread_rng();
        (0..count).map(|_| rng.gen()).collect()
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

    use super::{BytesCryptoExt, StreamCipher};

    pub fn encrypt(mut data: Vec<u8>, key: &[u8]) -> Vec<Vec<u8>> {
        let key = GenericArray::from_slice(key);
        let cipher = Aes128::new(key);

        data.pad_pkcs7(16);
        data.chunks(16)
            .map(move |block| {
                let mut block = GenericArray::clone_from_slice(block);
                cipher.encrypt_block(&mut block);
                block.to_vec()
            })
            .collect()
    }

    pub fn decrypt<'a, 'b>(data: &'a [u8], key: &'b [u8]) -> impl Iterator<Item = Vec<u8>> + 'a {
        let key = GenericArray::from_slice(key);
        let cipher = Aes128::new(key);

        data.chunks(16).map(move |block| {
            let mut block = GenericArray::clone_from_slice(block);
            cipher.decrypt_block(&mut block);
            block.to_vec()
        })
    }

    pub fn encrypt_cbc(mut data: Vec<u8>, key: &[u8], iv: Vec<u8>) -> Vec<Vec<u8>> {
        let key = GenericArray::from_slice(key);
        let cipher = Aes128::new(key);

        data.pad_pkcs7(16);
        data.chunks(16)
            .scan(iv, move |prev_block, block| {
                // mix with the previous block
                let block = block.xor_ref(prev_block.iter());
                let mut block = GenericArray::clone_from_slice(&block);
                cipher.encrypt_block(&mut block);
                *prev_block = block.to_vec();
                Some(prev_block.clone())
            })
            .collect()
    }

    pub fn decrypt_cbc<'a, 'b>(
        data: &'a [u8],
        key: &'b [u8],
        iv: Vec<u8>,
    ) -> impl Iterator<Item = Vec<u8>> + 'a {
        let key = GenericArray::from_slice(key);
        let cipher = Aes128::new(key);

        data.chunks(16).scan(iv, move |prev_block, block| {
            let mut current_xor = block.to_vec();
            std::mem::swap(&mut current_xor, prev_block);

            let mut block = GenericArray::clone_from_slice(block);
            cipher.decrypt_block(&mut block);

            // mix with the previous block
            Some(block.xor_ref(current_xor.iter()))
        })
    }
}

pub fn detect_block_size<Enc>(f: Enc) -> (usize, usize)
where
    Enc: Fn(&[u8]) -> Vec<u8>,
{
    let empty_enc_size: usize = f(&[]).len();
    eprintln!("Empty payload ciphertext size: {}", empty_enc_size);

    for i in 1.. {
        let payload: Vec<_> = iter::repeat(b'A').take(i).collect();
        let enc_size: usize = f(&payload).len();
        eprintln!(
            "The size of the ciphertext of the payload {:?} is {}",
            payload, enc_size,
        );

        let diff = enc_size - empty_enc_size;

        if diff != 0 {
            let suffix_size = empty_enc_size - i;
            return (diff, suffix_size);
        }
    }

    unreachable!("The block size will be revealed eventually")
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

    #[test]
    fn pad_empty() {
        let mut v = Vec::<u8>::new();
        v.pad_pkcs7(5);

        assert_eq!(v, vec![5; 5]);
    }

    #[test]
    fn pad_to_block() {
        let mut v = vec![5_u8, 32, 16, 0, 4];
        v.pad_pkcs7(6);

        assert_eq!(v, vec![5, 32, 16, 0, 4, 1]);
    }

    #[test]
    fn padding_is_mandatory() {
        let mut v = vec![5_u8, 32, 16, 0, 4, 1];
        v.pad_pkcs7(6);

        assert_eq!(v, vec![5, 32, 16, 0, 4, 1, 6, 6, 6, 6, 6, 6]);
    }

    #[test]
    fn empty_string_has_no_padding() {
        let v = vec![];
        for block_size in 0..=16 {
            assert_eq!(v.pkcs7_padding_size(block_size), None);
        }
    }

    #[test]
    fn no_valid_padding_for_zero_block_size() {
        for byte in 0..=16 {
            let v = vec![byte];
            assert_eq!(v.pkcs7_padding_size(0), None);
        }
    }

    #[test]
    fn the_only_valid_padding_for_stream() {
        let v = vec![1];
        assert_eq!(v.pkcs7_padding_size(1), Some(1));

        for byte in 2..=16 {
            let v = vec![byte];
            assert_eq!(v.pkcs7_padding_size(1), None);
        }
    }

    #[test]
    fn not_enough_bytes_padding() {
        // https://cryptopals.com/sets/2/challenges/15
        let s = "ICE ICE BABY\u{05}\u{05}\u{05}\u{05}";
        assert_eq!(s.strip_pkcs7_padding(8), None);
    }

    #[test]
    fn bad_bytes_padding() {
        // https://cryptopals.com/sets/2/challenges/15
        let s = "ICE ICE BABY\u{01}\u{02}\u{03}\u{04}";
        assert_eq!(s.strip_pkcs7_padding(16), None);
    }

    #[test]
    fn good_padding() {
        // https://cryptopals.com/sets/2/challenges/15
        let s = "ICE ICE BABY\u{05}\u{05}\u{05}\u{05}\u{05}";
        assert_eq!(s.strip_pkcs7_padding(8).unwrap(), "ICE ICE BABY");
    }
}
