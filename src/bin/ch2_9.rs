use pals::BytesCryptoExt;

const PLAIN_TEXT: &str = "YELLOW SUBMARINE";

fn main() {
    let mut data: Vec<_> = PLAIN_TEXT.bytes().collect();
    data.pad_pkcs7(20);

    let padded = String::from_utf8(data).unwrap();
    println!("Padded string: {:?}", padded);

    assert_result(&padded)
}

fn assert_result(result: &str) {
    assert_eq!(result, "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}");
}
