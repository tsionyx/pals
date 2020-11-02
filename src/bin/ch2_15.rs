use pals::StrCryptoExt;

fn main() {
    let s = "ICE ICE BABY\u{04}\u{04}\u{04}\u{04}";
    assert_eq!(s.strip_pkcs7_padding(16).unwrap(), "ICE ICE BABY");
}
