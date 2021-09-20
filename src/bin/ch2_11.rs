use rand::Rng;

use pals::{aes_cypher, BytesCryptoExt};

fn main() {
    for i in 0..100 {
        println!("{}. ========================", i);
        detect_mode();
    }
}

fn detect_mode() {
    // at least 4 blocks of data should be used, to allow random bytes padding
    // to eat some data from the beginning (first block) and the end (last block)
    let data = vec![0; 64];

    let (enc, hidden_mode) = encrypt_random(&data);
    eprintln!("Encrypted data is: {:?}", enc);

    // take the second and third blocks
    let blocks: Vec<_> = enc.chunks(16).skip(1).take(2).collect();

    let detected_mode = if blocks[0] == blocks[1] {
        println!("The encryption was made with the EBC mode!");
        Mode::Ebc
    } else {
        println!("It is definitely NOT the EBC mode!");
        Mode::Cbc
    };

    assert_eq!(hidden_mode, detected_mode);
}

#[derive(Debug, PartialEq)]
enum Mode {
    Ebc,
    Cbc,
}

fn encrypt_random(data: &[u8]) -> (Vec<u8>, Mode) {
    let mut rng = rand::thread_rng();
    let bytes_before = rng.gen_range(5, 11);
    let bytes_after = rng.gen_range(5, 11);

    eprintln!("Original data to encrypt: {:?}", data);
    let mut salted = Vec::generate_random(bytes_before);
    salted.extend_from_slice(data);
    salted.extend(Vec::generate_random(bytes_after));
    eprintln!(
        "Add {} bytes to beginning and {} bytes to the end: {:?}",
        bytes_before, bytes_after, salted
    );

    let key = Vec::generate_random(16);
    eprintln!("Random key to encrypt: {:?}", key);
    if rng.gen() {
        println!("Encrypting in the EBC mode...");
        (aes_cypher::encrypt(salted, &key).concat(), Mode::Ebc)
    } else {
        let iv = Vec::generate_random(16);
        println!("Encrypting in the CBC mode...");
        (
            aes_cypher::encrypt_cbc(salted, &key, iv).concat(),
            Mode::Cbc,
        )
    }
}
