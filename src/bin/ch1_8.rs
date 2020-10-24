use std::{collections::HashMap, env, fs};

use pals::{aes_cypher, HexDisplay, StrCryptoExt};

const RANDOM_KEY: &str = "YELLOW SUBMARINE";

fn main() {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("8.txt");
    let hex = fs::read_to_string(data_f).unwrap();
    let data = hex.lines().map(StrCryptoExt::parse_hex);

    for (i, text) in data.enumerate() {
        let same_results = try_decrypt(&text, RANDOM_KEY.as_bytes());

        if let Some(true) = same_results {
            let hex = text.as_hex();
            println!(
                "{}-th Line {:?} has been ciphered in ECB mode for sure",
                i,
                text.as_hex()
            );
            assert_result(&hex, i);
        }
    }
}

fn try_decrypt(data: &[u8], key: &[u8]) -> Option<bool> {
    let mut processed_pairs = HashMap::new();

    for (block_number, (ciphered, deciphered)) in data
        .chunks(16)
        .zip(aes_cypher::decrypt(data, key))
        .enumerate()
    {
        if let Some(before) = processed_pairs.get(&ciphered) {
            eprintln!("{}.{:?}", block_number, ciphered.as_hex());
            return Some(before == &deciphered);
        }

        processed_pairs.insert(ciphered, deciphered);
    }

    None
}

fn assert_result(result: &str, line_number: usize) {
    assert!(result.starts_with("d880619740"));
    assert_eq!(line_number, 132);
}
