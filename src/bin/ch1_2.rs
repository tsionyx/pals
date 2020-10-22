use pals::{parse_hex, xor};

const A: &str = "1c0111001f010100061a024b53535009181c";
const B: &str = "686974207468652062756c6c277320657965";

fn main() {
    let raw1 = parse_hex(A);
    let raw2 = parse_hex(B);

    let data: Vec<_> = xor!(raw1.iter(), raw2).collect();
    eprintln!("{:x?}", data);

    let x: String = data.into_iter().map(|x| format!("{:x}", x)).collect();
    println!("{}", x)
}
