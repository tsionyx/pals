use pals::{HexDisplay, StrCryptoExt, StreamCipher};

const A: &str = "1c0111001f010100061a024b53535009181c";
const B: &str = "686974207468652062756c6c277320657965";

fn main() {
    let raw1 = A.parse_hex();
    let raw2 = B.parse_hex();

    let data = raw1.xor(raw2.into_iter());
    eprintln!("{:x?}", data);

    let hex = data.as_hex();
    println!("{}", hex);

    assert_result(&hex);
}

fn assert_result(result: &str) {
    assert!(result.starts_with("7468"));
    assert!(result.ends_with("c6179"));
}
