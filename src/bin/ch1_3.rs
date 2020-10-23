use pals::{BytesCryptoExt, StrCryptoExt};

const ENCODED: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

fn main() {
    let candidates = ENCODED.parse_hex().guess_the_single_char_xor_key();
    for (key, plain, score) in &candidates[..2] {
        if !plain.is_printable_ascii() {
            continue;
        }

        println!(
            "The key is {}({:?}). Plaintext is: {:?} (score={})",
            key, *key as char, plain, score
        );
    }
}
