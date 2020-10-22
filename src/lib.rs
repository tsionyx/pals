#![allow(clippy::must_use_candidate)]

use itertools::Itertools;

/// <https://codereview.stackexchange.com/a/201699>
pub fn parse_hex(hex_asm: &str) -> Vec<u8> {
    let hex_bytes = hex_asm
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    hex_bytes.tuples().map(|(h, l)| h << 4 | l).collect()
}
