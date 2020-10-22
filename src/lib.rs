#![allow(clippy::must_use_candidate)]

use std::iter;

use itertools::Itertools;

pub mod freq;

/// <https://codereview.stackexchange.com/a/201699>
pub fn parse_hex(hex_asm: &str) -> Vec<u8> {
    let hex_bytes = hex_asm
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

// pub fn xor2<'a, I1, I2, T>(a: I1, b: I2) -> impl Iterator<Item=T>
//     where I1: Iterator<Item=&'a T>, I2: IntoIterator<Item=T>, T: 'a + std::ops::BitXor<Output=T> {
//     a.zip(b).map(|(x, y)| x ^ y)
// }

#[macro_export]
macro_rules! xor {
    ($a:expr, $b:expr) => {
        $a.zip($b).map(|(x, y)| x ^ y)
    };
}

/// Higher score signifies the text is going further away from
/// the standard english text (in terms of letter's frequencies
fn english_text_score(text: &str) -> f64 {
    let standard = freq::eng_map();
    let real = freq::letters_frequencies(text);
    standard
        .into_iter()
        .map(|(ch, std_freq)| {
            real.get(&ch).map_or(1.0, |freq| {
                // the close to standard, the lower the score
                (std_freq - freq).abs()
            })
        })
        .sum()
}

pub fn break_the_single_char_xor(raw: &[u8]) -> Vec<(u8, String, f64)> {
    eprintln!("{:x?}", raw);

    let keys_space = 0..=u8::MAX;
    let mut candidates: Vec<_> = keys_space
        .filter_map(|key| {
            let full_key = iter::repeat(key);
            let raw = xor!(raw.iter(), full_key).collect();
            String::from_utf8(raw).ok().map(|plain| {
                let score = english_text_score(&plain);
                (key, plain, score)
            })
        })
        .collect();

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    candidates.sort_unstable_by_key(|(_key, _plain, score)| (score * 1000.0) as u64);

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
pub fn find_key_char(line: &[u8]) -> Result<u8, String> {
    let candidates = break_the_single_char_xor(line);
    if candidates.is_empty() {
        return Err("No valid key char can be found".to_string());
    }

    eprintln!(
        "Trying to decrypt the line {:?} with single character",
        line
    );

    for (key, plain, score) in &candidates {
        // unprintable non-whitespace symbol
        if !is_printable_ascii(plain) {
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

pub fn is_printable_ascii(text: &str) -> bool {
    text.chars()
        .all(|ch| ch.is_ascii_whitespace() || !ch.is_ascii_control())
}

pub fn hamming(lhs: impl AsRef<[u8]>, rhs: impl AsRef<[u8]>) -> u32 {
    lhs.as_ref()
        .iter()
        .zip(rhs.as_ref())
        .map(|(l, r)| (l ^ r).count_ones())
        .sum()
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
