use std::iter;

use self::blackbox::Profile;
use pals::BytesCryptoExt;

mod blackbox {
    use std::collections::HashMap;

    use itertools::Itertools;
    use lazy_static::lazy_static;

    use pals::{aes_cypher, BytesCryptoExt};

    lazy_static! {
        static ref KEY: Vec<u8> = Vec::generate_random(16);
    }

    fn get_profile(email: &str) -> Vec<(&str, String)> {
        let email = email.replace(|ch| (ch == '&') || (ch == '='), "");
        vec![
            ("email", email),
            ("uid", "10".into()),
            ("role", "user".into()),
        ]
    }

    fn parse_cookie(s: &str) -> Vec<(String, String)> {
        s.split('&')
            .map(|pair| {
                let mut splitted = pair.split('=');
                let k = splitted.next().unwrap();
                let v = splitted.next().unwrap();
                (k.to_string(), v.to_string())
            })
            .collect()
    }

    fn fmt_pairs(data: &[(&str, String)]) -> String {
        data.iter().map(|(k, v)| format!("{}={}", k, v)).join("&")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn user_profile() {
            assert_eq!(
                get_profile("a@aa.aa"),
                vec![
                    ("email", "a@aa.aa".to_string()),
                    ("uid", "10".into()),
                    ("role", "user".into()),
                ]
            );
        }

        #[test]
        fn user_profile_no_email_injection() {
            assert_eq!(
                get_profile("foo@bar.com&role=admin"),
                vec![
                    ("email", "foo@bar.comroleadmin".to_string()),
                    ("uid", "10".into()),
                    ("role", "user".into()),
                ]
            );
        }

        #[test]
        fn cookie_parse_sanity_check() {
            let x = parse_cookie("foo=bar&baz=qux&zap=zazzle");
            assert_eq!(
                x,
                &[
                    ("foo".to_string(), "bar".to_string()),
                    ("baz".to_string(), "qux".to_string()),
                    ("zap".to_string(), "zazzle".to_string())
                ]
            );
        }

        #[test]
        fn cookie_fmt_in_order() {
            let data = vec![
                ("email", "foo@bar.com".to_string()),
                ("uid", "10".into()),
                ("role", "user".into()),
            ];
            let s = fmt_pairs(&data);
            assert_eq!(s, "email=foo@bar.com&uid=10&role=user");
        }
    }

    pub fn profile_for(email: &str) -> Vec<u8> {
        let x = fmt_pairs(&get_profile(email));
        aes_cypher::encrypt(x.bytes().collect(), &KEY).concat()
    }

    pub fn decrypt_profile(profile_enc: &[u8]) -> Option<Profile> {
        let mut profile_bytes = aes_cypher::decrypt(profile_enc, &KEY).concat();
        eprintln!(
            "Profile bytes: {:?}",
            String::from_utf8(profile_bytes.clone())
        );
        profile_bytes.unpad_pkcs7(16);
        Profile::from_cookie(&String::from_utf8(profile_bytes).unwrap())
    }

    #[derive(Debug)]
    pub struct Profile {
        email: String,
        uid: String,
        role: String,
    }

    impl Profile {
        fn from_cookie(formatted: &str) -> Option<Self> {
            let mut data: HashMap<_, _> = parse_cookie(formatted).into_iter().collect();
            let email = data.remove("email")?;
            let uid = data.remove("uid")?;
            let role = data.remove("role")?;

            Some(Self { email, uid, role })
        }

        pub fn email(&self) -> &str {
            &self.email
        }

        pub fn role(&self) -> &str {
            &self.role
        }
    }
}

fn elevate_privileges() -> Profile {
    // Craft the first block
    // "email=xxxx@acme."
    // <---------------->
    //          16
    let block_size = 16;
    let email_prefix = "email=";
    let email_suffix_in_block = "@acme.";
    let fill_in = block_size - email_prefix.len() - email_suffix_in_block.len();
    let email_username: String = iter::repeat('x').take(fill_in).collect();

    // Craft the second block
    // "admin[PADDING_BYTES]"
    // <------------------->
    //            16
    let target_role = "admin";
    let mut role_with_padding = target_role.as_bytes().to_vec();
    #[allow(clippy::cast_possible_truncation)]
    role_with_padding.pad_pkcs7(block_size as u8);
    let role_str = String::from_utf8(role_with_padding).unwrap();

    // Craft the third block
    // "ccc&uid=10&role="
    // <---------------->
    //          16
    let mandatory_structure = "&uid=10&role=";
    let email_real_suffix_fill_in = block_size - mandatory_structure.len();
    let email_real_suffix: String = iter::repeat('c').take(email_real_suffix_fill_in).collect();

    let email = vec![
        email_username,
        email_suffix_in_block.to_string(),
        role_str,
        email_real_suffix,
    ]
    .concat();
    eprintln!("Full email with injected payload: {:?}", email);
    let enc_profile = blackbox::profile_for(&email);

    let blocks: Vec<_> = enc_profile.chunks(16).collect();
    let admin_profile_enc = vec![blocks[0], blocks[2], blocks[1]].concat();
    blackbox::decrypt_profile(&admin_profile_enc).unwrap()
}

fn main() {
    let profile = elevate_privileges();
    println!("Generated profile: {:?}", profile);
    assert_result(&profile);
}

fn assert_result(profile: &Profile) {
    assert_eq!(profile.email(), "xxxx@acme.ccc");
    assert_eq!(profile.role(), "admin");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_roundtrip() {
        let profile = blackbox::profile_for("foo@acme.com");
        let profile = blackbox::decrypt_profile(&profile).unwrap();
        assert_eq!(profile.role(), "user");
    }
}
