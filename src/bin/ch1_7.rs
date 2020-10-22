use aes::{cipher::generic_array::GenericArray, Aes128, BlockCipher, NewBlockCipher};
use std::{env, fs};

const KEY: &str = "YELLOW SUBMARINE";

fn main() {
    let wd = env::current_dir().unwrap();
    let data_f = wd.join("data").join("7.txt");
    let base64_ed = fs::read_to_string(data_f).unwrap();

    // remove the newlines
    let base64_ed = base64_ed.replace('\n', "");
    let data = base64::decode(base64_ed).unwrap();

    let key = GenericArray::from_slice(KEY.as_bytes());
    let cipher = Aes128::new(key);

    for block in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut block);
        print!("{}", String::from_utf8(block.to_vec()).unwrap());
    }
}
