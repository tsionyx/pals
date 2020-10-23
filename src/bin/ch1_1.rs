use base64::encode;
use pals::StrCryptoExt;

const HEX_REPR: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

fn main() {
    eprintln!("Hex representation: {}", HEX_REPR);

    let raw = HEX_REPR.parse_hex();
    eprintln!("Raw bytes representation: {:?}", &raw);

    let encoded = encode(&raw);
    println!("{}", encoded);

    assert_result(&encoded)
}

fn assert_result(result: &str) {
    assert!(result.starts_with("SSdt"));
    assert!(result.ends_with("2hyb29t"));
}
