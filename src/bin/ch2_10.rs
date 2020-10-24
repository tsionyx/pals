use pals::aes_cypher;
use std::{env, fs};

const KEY: &str = "YELLOW SUBMARINE";

fn main() {
    let iv = vec![0; 16];
    let data = read_cipher_text();
    let mut full_str = Vec::new();

    for block in aes_cypher::decrypt_cbc(&data, KEY.as_bytes(), iv) {
        let block_dec = String::from_utf8(block).unwrap();
        print!("{}", block_dec);
        full_str.push(block_dec);
    }

    let full_str: String = full_str.concat().trim_end().into();
    assert_result(full_str);
}

fn read_cipher_text() -> Vec<u8> {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("10.txt");
    let base64_ed = fs::read_to_string(data_f).unwrap();

    // remove the newlines
    let base64_ed = base64_ed.replace('\n', "");
    base64::decode(base64_ed).unwrap()
}

fn assert_result(mut text: String) {
    assert!(text.starts_with("I'm back and I'm ringin' the bell"));

    let padding = String::from_utf8(vec![4; 4]).unwrap();
    assert!(text.ends_with(&padding));
    text.truncate(text.len() - padding.len());

    assert!(text.trim_end().ends_with("Play that funky music"));
}
