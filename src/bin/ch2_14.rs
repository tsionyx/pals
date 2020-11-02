use std::iter;

mod blackbox {
    use std::sync::Mutex;

    use lazy_static::lazy_static;
    use rand::Rng;

    use pals::{aes_cypher, BytesCryptoExt};

    lazy_static! {
        static ref KEY: Vec<u8> = Vec::generate_random(16);
        static ref RANDOM_PREFIX: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    }

    fn get_prefix() -> Vec<u8> {
        let mut guard = RANDOM_PREFIX.lock().unwrap();

        if let Some(prefix) = &*guard {
            return prefix.clone();
        }

        let mut rng = rand::thread_rng();
        let prefix_size = rng.gen_range(100, 1000);
        let result = Vec::generate_random(prefix_size);
        *guard = Some(result.clone());
        result
    }

    const UNKNOWN_PLAINTEXT: &str = r#"
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"#;

    fn get_suffix() -> Vec<u8> {
        let base64_ed = UNKNOWN_PLAINTEXT.replace('\n', "");
        base64::decode(base64_ed).unwrap()
    }

    pub fn encrypt(data: &[u8]) -> Vec<Vec<u8>> {
        let prefix = get_prefix();
        let suffix = get_suffix();

        // eprintln!("Original data to encrypt: {:?}", data);
        // eprintln!(
        //     "Lengths of: prefix: {}, data: {}, suffix: {}",
        //     prefix.len(), data.len(), suffix.len());

        let data = prefix
            .into_iter()
            .chain(data.to_vec())
            .chain(suffix)
            .collect();

        // eprintln!(
        //     "Final data to encrypt with the key {:?}: {:?} (size={})",
        //     KEY.as_slice(), data, data.len());
        aes_cypher::encrypt(data, &KEY)
    }
}

/// A set of tools to reveal some information about plaintext
/// encrypted with the block cipher in EBC mode
struct EbcBreaking<Enc>
where
    Enc: Fn(&[u8]) -> Vec<u8>,
{
    enc_f: Enc,
    block_size: usize,
    fixed_parts_size: usize,
}

impl<Enc> EbcBreaking<Enc>
where
    Enc: Fn(&[u8]) -> Vec<u8>,
{
    fn new(enc_f: Enc) -> Self {
        let (block_size, fixed_parts_size) = Self::detect_block_size(&enc_f);
        Self {
            enc_f,
            block_size,
            fixed_parts_size,
        }
    }

    fn detect_block_size(enc_f: &Enc) -> (usize, usize) {
        let empty_enc_size: usize = enc_f(&[]).len();
        eprintln!("Empty payload ciphertext size: {}", empty_enc_size);

        for padding_size in 1.. {
            let payload = Self::same_symbols_data(padding_size);
            let enc_size: usize = enc_f(&payload).len();
            eprintln!(
                "The size of the ciphertext of the payload {:?} is {}",
                payload, enc_size,
            );

            let diff = enc_size - empty_enc_size;

            if diff != 0 {
                let fixed_data_size = empty_enc_size - padding_size;
                return (diff, fixed_data_size);
            }
        }

        unreachable!("The block size will be revealed eventually")
    }

    fn detect_mode(&self) -> Mode {
        let blocks_to_verify = 10;

        // at least X+2 blocks of data should be used, to allow random bytes padding
        // to eat some data from the beginning (first block) and the end (last block)
        // and detect at least X successive identical blocks
        let payload_size = self.block_size * (blocks_to_verify + 2);
        let enc_blocks = self.encrypt_same_symbols(payload_size);
        // eprintln!("Encrypted data is: {:?}", enc_blocks);

        let mut first_of_equal_blocks = 0;
        for (block_number, (block, next_block)) in
            enc_blocks.iter().zip(&enc_blocks[1..]).enumerate()
        {
            // eprintln!(
            //     "Is the {}-th block {:?} equals to block {:?}",
            //     block_number, block, next_block
            // );
            if block == next_block {
                if (block_number - first_of_equal_blocks) == blocks_to_verify - 1 {
                    // eprintln!(
                    //     "Found {} identical blocks {:?} in a row",
                    //     blocks_to_verify, block
                    // );
                    return Mode::Ebc {
                        prefix_blocks: first_of_equal_blocks,
                    };
                }
            } else {
                first_of_equal_blocks = block_number + 1;
            }
        }

        Mode::Cbc
    }

    fn detect_prefix_padding_size(&self) -> usize {
        if let Mode::Ebc {
            prefix_blocks: whole_blocks_for_prefix,
        } = self.detect_mode()
        {
            // if whole_blocks_for_prefix == 0 {
            //     return 0;
            // }
            // Take two blocks of 'A' to get the 'A'-block encrypted representation.
            // E.g. whole_blocks_for_prefix = 5
            //
            //   data | --- prefix --- |AAA|AAA|
            // blocks | 0 | 1 | 2 | 3 | 4 | 5 | 6 |
            let enc_blocks = self.encrypt_same_symbols(self.block_size * 2);
            let a_block = &enc_blocks[whole_blocks_for_prefix];
            // eprintln!(
            //     "The encrypted 'AAAA' block ({}-th) looks like {:?}",
            //     whole_blocks_for_prefix, enc_blocks
            // );

            //                    find this gap's size
            //                          VV
            //   data | --- prefix --- |AA|AAA|
            // blocks | 0 | 1 | 2 | 3 | 4 | 5 |
            for pad_size in 0..self.block_size * 2 {
                let enc_blocks = self.encrypt_same_symbols(pad_size);
                // eprintln!(
                //     "The encrypted blocks with padding of {} bytes looks like {:?}",
                //     pad_size, enc_blocks
                // );
                if enc_blocks.get(whole_blocks_for_prefix) == Some(a_block) {
                    return pad_size % self.block_size;
                }
            }

            unreachable!("The padding size should compute eventually");
        }

        panic!("Prefix detection only works in the EBC mode")
    }

    fn get_prefix_components(&self) -> (usize, usize) {
        if let Mode::Ebc { prefix_blocks } = self.detect_mode() {
            let prefix_padding_size = self.detect_prefix_padding_size();
            return (prefix_blocks, prefix_padding_size);
        }

        panic!("Prefix detection only works in the EBC mode")
    }

    fn get_prefix_exact_size(&self) -> usize {
        let (prefix_blocks, prefix_padding_size) = self.get_prefix_components();
        prefix_blocks * self.block_size - prefix_padding_size
    }

    fn get_suffix_exact_sizes(&self) -> usize {
        let prefix_size = self.get_prefix_exact_size();
        self.fixed_parts_size - prefix_size
    }

    fn detect_byte(
        &self,
        short_payload: &[u8],
        target_block_number: usize,
        expected_block: &[u8],
    ) -> Option<u8> {
        for i in 0..std::u8::MAX {
            let mut crafted_payload = short_payload.to_vec();
            crafted_payload.push(i);

            let enc = self.encrypt_blocks(&crafted_payload);
            if enc.get(target_block_number).map(Vec::as_slice) == Some(expected_block) {
                eprintln!(
                    "The result of encrypting the block {:?} is {:?} (in the {}-th position)",
                    crafted_payload, expected_block, target_block_number,
                );
                return Some(i);
            }
        }

        None
    }

    fn encrypt_blocks(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let enc_blocks = (self.enc_f)(data);
        enc_blocks
            .chunks(self.block_size)
            .map(<[_]>::to_vec)
            .collect()
    }

    fn same_symbols_data(size: usize) -> Vec<u8> {
        iter::repeat(b'A').take(size).collect()
    }

    fn encrypt_same_symbols(&self, size: usize) -> Vec<Vec<u8>> {
        let payload = Self::same_symbols_data(size);
        self.encrypt_blocks(&payload)
    }

    fn detect_suffix(&self) -> Vec<u8> {
        let (prefix_blocks, prefix_padding_size) = self.get_prefix_components();
        let suffix_size = self.get_suffix_exact_sizes();
        dbg!(prefix_blocks);
        dbg!(prefix_padding_size);
        dbg!(suffix_size);

        let mut result = Vec::with_capacity(suffix_size);

        // let data_first_block = prefix_size / block_size

        for byte_number in 0..suffix_size {
            let byte_offset = byte_number % self.block_size;
            let block_number = byte_number / self.block_size;
            eprintln!(
                "Decrypting the suffix's {}-th byte. Offset is {}. Block number is {}",
                byte_number, byte_offset, block_number
            );
            let one_byte_shorter = self.block_size - byte_offset - 1;
            let short_payload = Self::same_symbols_data(prefix_padding_size + one_byte_shorter);
            assert_eq!(
                short_payload.len(),
                prefix_padding_size + self.block_size - byte_offset - 1
            );

            let short_template = self.encrypt_blocks(&short_payload);
            let short_block = &short_template[prefix_blocks + block_number];
            eprintln!(
                "The result of encrypting the short block {:?} is {:?}",
                short_payload, short_block
            );

            // always left only one unrevealed byte in the first block
            let brute_force_payload_target_len = prefix_padding_size + self.block_size - 1;

            let brute_force_payload = if block_number == 0 {
                let mut payload = short_payload.clone();
                payload.extend_from_slice(&result[..byte_number]);
                payload
            } else {
                let known_suffix_part =
                    result[byte_number - self.block_size + 1..byte_number].to_vec();
                Self::same_symbols_data(prefix_padding_size)
                    .into_iter()
                    .chain(known_suffix_part)
                    .collect()
            };
            assert_eq!(brute_force_payload.len(), brute_force_payload_target_len);

            let detected_byte = self.detect_byte(&brute_force_payload, prefix_blocks, short_block);
            result.push(detected_byte.unwrap());
        }

        result
    }
}

#[derive(Debug, PartialEq)]
enum Mode {
    Ebc { prefix_blocks: usize },
    Cbc,
}

fn main() {
    let ebc = EbcBreaking::new(|data| blackbox::encrypt(data).concat());
    let suffix = String::from_utf8(ebc.detect_suffix()).unwrap();
    println!("{}", suffix);
    assert_result(&suffix);
}

fn assert_result(result: &str) {
    assert!(result.starts_with("Rollin' in my 5.0"));
    assert!(result
        .trim_end()
        .ends_with("Did you stop? No, I just drove by"));
}

#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use rand::Rng;

    use pals::{aes_cypher, BytesCryptoExt};

    use super::*;

    lazy_static! {
        static ref KEY: Vec<u8> = Vec::generate_random(16);
    }

    fn encrypt_with_prefix_and_suffix(
        prefix: Vec<u8>,
        suffix: Vec<u8>,
    ) -> impl Fn(&[u8]) -> Vec<u8> {
        // TODO: get rid of clones
        move |data| {
            let data: Vec<_> = prefix
                .clone()
                .into_iter()
                .chain(data.to_vec())
                .chain(suffix.clone())
                .collect();

            aes_cypher::encrypt(data, &KEY).concat()
        }
    }

    fn encrypt_with_prefix(prefix: Vec<u8>) -> impl Fn(&[u8]) -> Vec<u8> {
        encrypt_with_prefix_and_suffix(prefix, vec![])
    }

    #[test]
    fn detect_block_size_no_additional_data() {
        let f = encrypt_with_prefix(vec![]);
        let ebc = EbcBreaking::new(f);
        assert_eq!(ebc.block_size, 16);
        assert_eq!(ebc.fixed_parts_size, 0);
    }

    #[test]
    fn detect_block_size_random_prefix() {
        let mut rng = rand::thread_rng();
        for _i in 0..10 {
            let prefix_size = rng.gen_range(100, 1000);
            let f = encrypt_with_prefix(vec![42; prefix_size]);

            let ebc = EbcBreaking::new(f);
            assert_eq!(ebc.block_size, 16);
            assert_eq!(ebc.fixed_parts_size, prefix_size);
        }
    }

    #[test]
    fn detect_block_size_random_prefix_and_suffix() {
        let mut rng = rand::thread_rng();
        for _i in 0..10 {
            let prefix_size = rng.gen_range(100, 1000);
            let suffix_size = rng.gen_range(100, 1000);
            let f = encrypt_with_prefix_and_suffix(vec![42; prefix_size], vec![28; suffix_size]);

            let ebc = EbcBreaking::new(f);
            assert_eq!(ebc.block_size, 16);
            assert_eq!(ebc.fixed_parts_size, prefix_size + suffix_size);
        }
    }

    #[test]
    fn check_mode_detect_no_prefix() {
        let f = encrypt_with_prefix(vec![]);
        let ebc = EbcBreaking::new(f);

        assert_eq!(ebc.detect_mode(), Mode::Ebc { prefix_blocks: 0 });
        assert_eq!(ebc.detect_prefix_padding_size(), 0);
    }

    #[test]
    fn check_mode_detect_minimal_prefix() {
        let f = encrypt_with_prefix(vec![1]);
        let ebc = EbcBreaking::new(f);

        assert_eq!(ebc.detect_mode(), Mode::Ebc { prefix_blocks: 1 });
        assert_eq!(ebc.detect_prefix_padding_size(), 15);
    }

    #[test]
    fn check_mode_detect_whole_block_prefix() {
        let f = encrypt_with_prefix(vec![1; 16]);
        let ebc = EbcBreaking::new(f);

        assert_eq!(ebc.detect_mode(), Mode::Ebc { prefix_blocks: 1 });
        assert_eq!(ebc.detect_prefix_padding_size(), 0);
    }

    #[test]
    fn check_mode_detect_several_blocks_prefix() {
        let f = encrypt_with_prefix(vec![1; 48]);
        let ebc = EbcBreaking::new(f);

        assert_eq!(ebc.detect_mode(), Mode::Ebc { prefix_blocks: 3 });
        assert_eq!(ebc.detect_prefix_padding_size(), 0);
    }

    #[test]
    fn check_mode_detect_uneven_blocks_prefix() {
        for i in 49..=64 {
            let f = encrypt_with_prefix(vec![1; i]);
            let ebc = EbcBreaking::new(f);

            assert_eq!(ebc.detect_mode(), Mode::Ebc { prefix_blocks: 4 });
            assert_eq!(ebc.detect_prefix_padding_size(), 64 - i);
        }

        let f = encrypt_with_prefix(vec![1; 65]);
        let ebc = EbcBreaking::new(f);

        assert_eq!(ebc.detect_mode(), Mode::Ebc { prefix_blocks: 5 });
        assert_eq!(ebc.detect_prefix_padding_size(), 15);
    }

    #[test]
    fn check_prefix_size_invariants() {
        let mut rng = rand::thread_rng();
        for _i in 0..30 {
            // TODO: increase the possible prefix to cover more than 10 blocks
            let prefix_size = rng.gen_range(100, 160);
            dbg!(prefix_size);

            let f = encrypt_with_prefix(vec![255; prefix_size]);
            let ebc = EbcBreaking::new(f);

            let (prefix_blocks, prefix_padding_size) = ebc.get_prefix_components();
            dbg!(prefix_blocks);
            dbg!(prefix_padding_size);

            assert_eq!(
                (prefix_padding_size + prefix_size),
                prefix_blocks * ebc.block_size
            );
            assert_eq!(ebc.get_prefix_exact_size(), prefix_size)
        }
    }
}
