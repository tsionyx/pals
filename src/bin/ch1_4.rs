use std::{env, fs};

use pals::{BytesCryptoExt, StrCryptoExt};

const CANDIDATES_TO_TRY: usize = 2;

fn main() {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("4.txt");
    let data = fs::read_to_string(data_f).unwrap();

    for (i, line) in data.lines().enumerate() {
        let candidates = line.parse_hex().guess_the_single_char_xor_key();
        if candidates.is_empty() {
            continue;
        }

        eprintln!("{}-th LINE: {:?}", i, line);
        for (key, plain, score) in &candidates[..CANDIDATES_TO_TRY] {
            if !plain.is_printable_ascii() {
                continue;
            }

            println!(
                "The key is {}({:?}). Plaintext is: {:?} (score={})",
                key, *key as char, plain, score
            );

            assert_result(plain, *key as char);
        }
    }
}

fn assert_result(result: &str, key: char) {
    assert_eq!(result, "Now that the party is jumping\n");
    assert_eq!(key, '5');
}
