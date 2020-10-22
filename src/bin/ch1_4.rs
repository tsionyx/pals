use std::{env, fs};

use pals::{break_the_single_char_xor, is_printable_ascii, parse_hex};

const CANDIDATES_TO_TRY: usize = 2;

fn main() {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("4.txt");
    let data = fs::read_to_string(data_f).unwrap();

    for (i, line) in data.lines().enumerate() {
        let candidates = break_the_single_char_xor(&parse_hex(line));
        if candidates.is_empty() {
            continue;
        }

        eprintln!("{}. {}", i, line);
        for (key, plain, score) in &candidates[..CANDIDATES_TO_TRY] {
            if !is_printable_ascii(plain) {
                continue;
            }

            println!(
                "The key is {}({:?}). Plaintext is: {:?} (score={})",
                key, *key as char, plain, score
            );
        }
    }
}
