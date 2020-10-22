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

pub fn break_the_single_char_xor(cipher_text: &str) -> Vec<(u8, String, f64)> {
    let raw = parse_hex(cipher_text);

    eprintln!("{:x?}", raw);

    let keys_space = 0..=255;
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

    if candidates.len() >= 10 {
        for (key, plain, score) in &candidates[..10] {
            eprintln!("{} ({}). {} -> {}", key, *key as char, plain, score);
        }
    }

    candidates
}
