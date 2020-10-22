use std::{env, fs};

use pals::break_the_single_char_xor;

fn main() {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("4.txt");
    let data = fs::read_to_string(data_f).unwrap();

    for (i, line) in data.lines().enumerate() {
        let candidates = break_the_single_char_xor(line);
        if candidates.is_empty() {
            continue;
        }

        println!("{}. {}", i, line);
        for (key, plain, score) in &candidates[..2] {
            // unprintable non-whitespace symbol
            if plain
                .chars()
                .any(|ch| ch.is_ascii_control() && !ch.is_ascii_whitespace())
            {
                continue;
            }

            println!(
                "The key is {}({:?}). Plaintext is: {:?} (score={})",
                key, *key as char, plain, score
            );
        }
    }
}
