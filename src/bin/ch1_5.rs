use std::{env, fs, io::Read};

use pals::{HexDisplay, StreamCipher};

const PLAIN: &str = r#"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"#;

const KEY: &str = "ICE";

fn main() {
    let ciphered = PLAIN.xor(KEY.bytes());

    let hex = ciphered.as_hex();
    println!("{}", hex);
    assert_result(&hex);

    let mut args = env::args();
    // skip the program name
    args.next();

    if let Some(out_file) = args.next() {
        let mut data = Vec::new();
        let size_of_data = std::io::stdin().read_to_end(&mut data).unwrap();
        eprintln!("Read {} bytes from stdin", size_of_data);
        encrypt_xor(&data, KEY, &out_file);
    }
}

fn assert_result(result: &str) {
    assert!(result.starts_with("b3637272"));
    assert!(result.trim_end().ends_with("2e27282f"));
}

fn encrypt_xor(data: &[u8], key: &str, out_file: &str) {
    let ciphered = data.xor(key.bytes());
    eprintln!("Saving the ciphered bytes into {:?}...", out_file);
    fs::write(out_file, ciphered).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs::File,
        process::{Command, Stdio},
    };

    fn run_command(cmd: &str, args: Vec<&str>, input_file: Option<&str>) -> String {
        #[allow(clippy::option_if_let_else)]
        let child = if let Some(input_file) = input_file {
            let stdin_file = File::open(input_file).unwrap();
            Command::new(cmd)
                .args(args)
                .stdout(Stdio::piped())
                .stdin(stdin_file)
                .spawn()
        } else {
            Command::new(cmd).args(args).stdout(Stdio::piped()).spawn()
        }
        .expect("Failed to start the process");

        let finished = child.wait_with_output().expect("Failed to wait for stdout");
        assert!(finished.status.success());

        String::from_utf8(finished.stdout).expect("Cannot parse the output as String")
    }

    fn md5sum(file_path: &str) -> String {
        run_command("md5sum", vec![file_path], None)[..32].to_string()
    }

    #[test]
    fn enc_and_dec() {
        // try to encrypt and decrypt this binary itself:
        // $ md5sum target/debug/ch1_5                       # remember this checksum!
        // $ cargo run --bin ch1_5 -- data.enc < target/debug/ch1_5
        // $ cargo run --bin ch1_5 -- data.orig < data.enc   # decrypting is the same for XOR
        // $ chmod +x data.orig
        // $ ./data.orig                                     # should output target text
        // $ md5sum data.orig                                # should match the original checksum

        let initial_sum = md5sum("target/debug/ch1_5");

        let enc_output = run_command(
            "target/debug/ch1_5",
            vec!["data.enc"],
            Some("target/debug/ch1_5"),
        );
        assert_result(&enc_output);
        let enc_sum = md5sum("data.enc");
        assert_ne!(initial_sum, enc_sum);

        let dec_output = run_command("target/debug/ch1_5", vec!["data.orig"], Some("data.enc"));
        assert_result(&dec_output);
        let dec_sum = md5sum("data.orig");
        assert_eq!(initial_sum, dec_sum);

        run_command("chmod", vec!["+x", "data.orig"], None);

        let restored_binary_output = run_command("./data.orig", vec![], None);
        assert_result(&restored_binary_output);

        fs::remove_file("data.enc").unwrap();
        fs::remove_file("data.orig").unwrap();
    }
}
