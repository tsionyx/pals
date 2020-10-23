use std::{env, fs, io::Read};

use pals::{HexDisplay, StreamCipher};

const PLAIN: &str = r#"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"#;

const KEY: &str = "ICE";

fn main() {
    let ciphered = PLAIN.xor(KEY.bytes());

    println!("{}", ciphered.as_hex());

    let mut args = env::args();
    // skip the program name
    args.next();

    if let Some(out_file) = args.next() {
        // try to encrypt and decrypt this binary itself:
        // $ md5sum target/debug/ch1_5                       # remember this checksum!
        // $ cargo run --bin ch1_5 -- data.enc < target/debug/ch1_5
        // $ cargo run --bin ch1_5 -- data.orig < data.enc   # decrypting is the same for XOR
        // $ chmod +x data.orig
        // $ ./data.orig                                     # should output target text
        // $ md5sum data.orig                                # should match the original checksum
        let mut data = Vec::new();
        let size_of_data = std::io::stdin().read_to_end(&mut data).unwrap();
        eprintln!("Read {} bytes from stdin", size_of_data);
        encrypt_xor(&data, KEY, &out_file)
    }
}

fn encrypt_xor(data: &[u8], key: &str, out_file: &str) {
    let ciphered = data.xor(key.bytes());
    eprintln!("Saving the ciphered bytes into {:?}...", out_file);
    fs::write(out_file, ciphered).unwrap();
}
