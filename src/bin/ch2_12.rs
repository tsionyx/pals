mod blackbox {
    use lazy_static::lazy_static;

    use pals::{aes_cypher, BytesCryptoExt};

    lazy_static! {
        static ref KEY: Vec<u8> = Vec::generate_random(16);
    }

    const UNKNOWN_PLAINTEXT: &str = r#"
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"#;

    pub fn encrypt(data: &[u8]) -> Vec<Vec<u8>> {
        // eprintln!("Original data to encrypt: {:?}", data);

        let base64_ed = UNKNOWN_PLAINTEXT.replace('\n', "");
        let suffix = base64::decode(base64_ed).unwrap();
        // eprintln!("Unknown suffix is {:?}", suffix);

        let data = data.iter().copied().chain(suffix).collect();
        // eprintln!(
        //     "Final data to encrypt with the key {:?}: {:?} (size={})",
        //     KEY.as_slice(), data, data.len());
        aes_cypher::encrypt(data, &KEY)
    }
}

mod breaking {
    use pals::detect_block_size;

    use super::blackbox::encrypt;

    fn detect_mode(block_size: usize) -> Mode {
        // at least 4 blocks of data should be used, to allow random bytes padding
        // to eat some data from the beginning (first block) and the end (last block)
        let data = vec![0; block_size * 4];

        let enc_blocks = encrypt(&data);
        // eprintln!("Encrypted data is: {:?}", enc_blocks);

        // take the second and third blocks (skip the first one as it can be padded)
        if enc_blocks[1] == enc_blocks[2] {
            Mode::Ebc
        } else {
            Mode::Cbc
        }
    }

    #[derive(Debug, PartialEq)]
    enum Mode {
        Ebc,
        Cbc,
    }

    fn detect_byte(short_payload: &[u8], expected_block: &[u8]) -> Option<u8> {
        for i in 0..std::u8::MAX {
            let mut crafted_payload = short_payload.to_vec();
            crafted_payload.push(i);

            let enc = encrypt(&crafted_payload);
            if enc[0] == expected_block {
                eprintln!(
                    "The result of encrypting the block {:?} is {:?}",
                    crafted_payload, enc[0]
                );
                return Some(i);
            }
        }

        None
    }

    fn detect_unknown(block_size: usize, unknown_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(unknown_size);

        for byte_number in 0..unknown_size {
            let byte_offset = byte_number % block_size;
            let block_number = byte_number / block_size;
            eprintln!(
                "Decrypting the {}-th byte. Offset is {}. Block number is {}",
                byte_number, byte_offset, block_number
            );
            let one_byte_shorter = block_size - byte_offset - 1;
            let short_payload: Vec<_> = "A".repeat(one_byte_shorter).into_bytes();

            let short_template = encrypt(&short_payload);
            let short_block = &short_template[block_number];
            eprintln!(
                "The result of encrypting the short block {:?} is {:?}",
                short_payload, short_block
            );

            let brute_force_payload = if block_number == 0 {
                let mut payload = short_payload;
                payload.extend_from_slice(&result[..byte_number]);
                payload
            } else {
                result[byte_number - block_size + 1..byte_number].to_vec()
            };
            // always left only one unrevealed byte in the first block
            assert_eq!(brute_force_payload.len(), block_size - 1);

            let detected_byte = detect_byte(&brute_force_payload, short_block);
            result.push(detected_byte.unwrap());
        }

        result
    }

    pub fn reveal_suffix() -> Vec<u8> {
        // 1. Discover the block size of the cipher. You know it, but do this step anyway.
        let (block_size, suffix_size) = detect_block_size(|data| encrypt(data).concat());
        println!(
            "The block size is {}. Suffix size is {}",
            block_size, suffix_size
        );

        // 2. Detect that the function is using ECB. You already know, but do this step anyways.
        if detect_mode(block_size) != Mode::Ebc {
            return vec![];
        }

        let unknown_suffix = detect_unknown(block_size, suffix_size);
        eprintln!("The suffix looks like {:?}", unknown_suffix);

        unknown_suffix
    }
}

fn main() {
    let unknown = String::from_utf8(breaking::reveal_suffix()).unwrap();
    println!("{}", unknown);
    assert_result(&unknown);
}

fn assert_result(result: &str) {
    assert!(result.starts_with("Rollin' in my 5.0"));
    assert!(result
        .trim_end()
        .ends_with("Did you stop? No, I just drove by"));
}
