use pals::{break_the_single_char_xor, is_printable_ascii, parse_hex};

const ENCODED: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn main() {
    let candidates = break_the_single_char_xor(&parse_hex(ENCODED));
    for (key, plain, score) in &candidates[..2] {
        if !is_printable_ascii(plain) {
            continue;
        }

        println!(
            "The key is {}({:?}). Plaintext is: {:?} (score={})",
            key, *key as char, plain, score
        );
    }
}
