use pals::{xor, HexDisplay, StrCryptoExt};

const A: &str = "1c0111001f010100061a024b53535009181c";
const B: &str = "686974207468652062756c6c277320657965";

fn main() {
    let raw1 = A.parse_hex();
    let raw2 = B.parse_hex();

    let data: Vec<_> = xor!(raw1.iter(), raw2).collect();
    eprintln!("{:x?}", data);

    println!("{}", data.as_hex())
}
