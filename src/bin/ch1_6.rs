use std::{env, fs};

use pals::{hamming, xor, BytesCryptoExt};

fn main() {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("6.txt");
    let base64_ed = fs::read_to_string(data_f).unwrap();

    // remove the newlines
    let base64_ed = base64_ed.replace('\n', "");
    // eprintln!("{:?}", base64_ed);

    let data = base64::decode(base64_ed).unwrap();
    // eprintln!("{:?}", data);

    decrypt_xor(&data);
}

fn decrypt_xor(data: &[u8]) {
    let key_size_candidates = determine_key_size(data);
    println!("KEYSIZE to choose from: {:?}", key_size_candidates);

    for key_size in key_size_candidates {
        println!("Trying to find the key of size {}...", key_size);
        let key = find_best_key(data, key_size);
        match key {
            Ok(key) => {
                let key_str = String::from_utf8(key.clone()).unwrap();
                println!("Found a key: {:?} ({:?})", key, key_str);
                println!("The text decrypted with this key");
                println!("=================================");
                let broken = xor!(data.iter(), key.iter().cycle()).collect();
                let data = String::from_utf8(broken).unwrap();
                println!("{}", data);
                println!("=================================");
            }
            Err(err) => {
                println!("The key size {} is bad: {:?}", key_size, err);
            }
        }
    }
}

fn find_best_key(data: &[u8], key_size: usize) -> Result<Vec<u8>, String> {
    let transposed_blocks =
        (0..key_size).map(|index| data.iter().skip(index).step_by(key_size).cloned().collect());

    transposed_blocks
        .map(|single_char_block: Vec<u8>| single_char_block.find_key_char())
        .collect()
}

const MAX_KEY_SIZE: usize = 40;
const BLOCKS_TO_ANALYZE_KEY_SIZE: usize = 5;
const KEY_SIZE_CANDIDATES: usize = 4;

fn determine_key_size(data: &[u8]) -> Vec<usize> {
    let mut distances: Vec<_> = (2..=MAX_KEY_SIZE)
        .map(|ks| (key_size_distance(data, ks), ks))
        .collect();

    distances.sort_unstable();
    eprintln!("{:?}", distances);

    distances
        .into_iter()
        .take(KEY_SIZE_CANDIDATES)
        .map(|(_distance, ks)| ks)
        .collect()
}

#[allow(clippy::cast_possible_truncation)]
fn key_size_distance(data: &[u8], key_size: usize) -> u32 {
    let blocks: Vec<_> = data
        .chunks(key_size)
        .take(BLOCKS_TO_ANALYZE_KEY_SIZE)
        .collect();

    let total_distance: u32 = blocks[1..]
        .iter()
        .zip(&blocks)
        .map(|(block1, block2)| {
            //println!("{}. {:?} - {:?} = {}", key_size, block1, block2, distance);
            hamming(block1, block2)
        })
        .sum();

    // normalized
    total_distance * 1000 / key_size as u32
}
