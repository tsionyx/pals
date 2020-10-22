use std::iter;

use pals::{
    freq::{eng_map, letters_frequencies},
    parse_hex, xor,
};

const ENCODED: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

/// Higher score signifies the text is going further away from
/// the standard english text (in terms of letter's frequencies
fn english_text_score(text: &str) -> f64 {
    let standard = eng_map();
    let real = letters_frequencies(text);
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

fn main() {
    let raw = parse_hex(ENCODED);

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

    for (key, plain, score) in &candidates[..10] {
        eprintln!("{} ({}). {} -> {}", key, *key as char, plain, score);
    }

    for (key, plain, _) in &candidates[..2] {
        println!("The key is {:?}. Plaintext is: {}", *key as char, plain);
    }
}
