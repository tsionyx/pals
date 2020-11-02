mod blackbox {
    use itertools::Itertools;
    use lazy_static::lazy_static;

    use pals::{aes_cypher, BytesCryptoExt};

    lazy_static! {
        static ref KEY: Vec<u8> = Vec::generate_random(16);
        static ref IV: Vec<u8> = Vec::generate_random(16);
    }

    fn get_entry(input: &str) -> String {
        let input = input.replace(|ch| (ch == ';') || (ch == '='), "");
        [
            "comment1=cooking%20MCs;userdata=",
            &input,
            ";comment2=%20like%20a%20pound%20of%20bacon",
        ]
        .concat()
    }

    fn parse_entry(s: &str) -> Vec<(String, String)> {
        s.split(';')
            .map(|pair| {
                let mut splitted = pair.split('=');
                let k = splitted.next().unwrap();
                let v = splitted.next().unwrap_or("");
                (k.to_string(), v.to_string())
            })
            .collect()
    }

    pub fn entry_for(data: &str) -> Vec<Vec<u8>> {
        let entry = get_entry(data);
        aes_cypher::encrypt_cbc(entry.into_bytes(), &KEY, IV.clone())
    }

    pub fn decrypt_entry(profile_enc: &[u8]) -> Option<String> {
        let mut entry_bytes = aes_cypher::decrypt_cbc(profile_enc, &KEY, IV.clone()).concat();
        entry_bytes.unpad_pkcs7(16);

        // TODO: check for valid UTF-8
        let entry = String::from_utf8_lossy(&entry_bytes);
        eprintln!("Entry bytes: {:?}", entry);

        parse_entry(&entry)
            .iter()
            .find_map(|(k, v)| if k == "admin" { Some(v.clone()) } else { None })
    }
}

fn elevate_privileges() -> Option<String> {
    // flipping the 3-rd bit (xor 4) of '?' produce the ';'
    // flipping the 2-rd bit (xor 2) of '?' produce the '='
    let target_block = "XXXXX?admin?true";

    let mut entry = blackbox::entry_for(target_block);
    // scramble the second (insignificant) block and force
    // the bitflipping in the third (target) block
    if let Some(second_block) = entry.get_mut(1) {
        second_block[5] ^= 4;
        second_block[11] ^= 2;
    }
    // let entry = &entry[1..];

    blackbox::decrypt_entry(&entry.concat())
}

fn main() {
    let is_admin_role = elevate_privileges();
    println!("Is admin role: {:?}", is_admin_role);
    assert_eq!(is_admin_role.unwrap(), "true");
}
