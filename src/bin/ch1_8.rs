use std::{collections::HashMap, env, fs};

use aes::{cipher::generic_array::GenericArray, Aes128, BlockCipher, NewBlockCipher};

use pals::parse_hex;

const RANDOM_KEY: &str = "YELLOW SUBMARINE";

fn main() {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("8.txt");
    let hex = fs::read_to_string(data_f).unwrap();
    let data = hex.lines().map(parse_hex);

    let key = GenericArray::from_slice(RANDOM_KEY.as_bytes());
    let cipher = Aes128::new(key);

    for (i, text) in data.enumerate() {
        let same_results = try_decrypt(&text, &cipher);

        if let Some(true) = same_results {
            let as_hex: String = text.iter().map(|x| format!("{:x}", x)).collect();
            println!(
                "{}-th Line {:?} has been ciphered in ECB mode for sure",
                i, as_hex
            );
        }
    }
}

fn try_decrypt(data: &[u8], cipher: &Aes128) -> Option<bool> {
    let mut processed_pairs = HashMap::new();

    for (block_number, block) in data.chunks(16).enumerate() {
        let ciphered = block.to_vec();
        let mut block = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut block);

        let deciphered = block.to_vec();
        if let Some(before) = processed_pairs.get(&ciphered) {
            let as_hex: String = ciphered.iter().map(|x| format!("{:x}", x)).collect();
            eprintln!("{}.{:?}", block_number, as_hex);
            return Some(before == &deciphered);
        }

        processed_pairs.insert(ciphered, deciphered);
    }

    None
}
