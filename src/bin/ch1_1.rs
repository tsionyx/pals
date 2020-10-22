use base64::encode;
use pals::parse_hex;

const HEX_REPR: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

fn main() {
    eprintln!("Hex representation: {}", HEX_REPR);

    let raw = parse_hex(HEX_REPR);
    eprintln!("Raw bytes representation: {:?}", &raw);

    println!("{}", encode(&raw));
}
