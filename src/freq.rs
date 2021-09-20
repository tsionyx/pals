use std::{collections::HashMap, hash::Hash};

pub fn letters_frequencies(text: &str) -> HashMap<char, f64> {
    let valid_chars = text.chars().filter_map(|ch| {
        if ch.is_ascii_alphabetic() {
            Some(ch.to_ascii_uppercase())
        } else {
            None
        }
    });
    let counter = count_reps(valid_chars);

    let total_chars: usize = counter.values().sum();

    #[allow(clippy::cast_precision_loss)]
    counter
        .into_iter()
        .map(|(k, v)| (k, v as f64 / total_chars as f64))
        .collect()
}

fn count_reps<T>(iter: impl Iterator<Item = T>) -> HashMap<T, usize>
where
    T: Hash + Eq,
{
    let mut counter = HashMap::new();
    for x in iter {
        counter.entry(x).and_modify(|v| *v += 1).or_insert(1);
    }
    counter
}

const LETTER_FREQ: [(char, f64); 26] = [
    ('A', 0.0817),
    ('B', 0.0150),
    ('C', 0.0278),
    ('D', 0.0425),
    ('E', 0.1270),
    ('F', 0.0223),
    ('G', 0.0202),
    ('H', 0.0609),
    ('I', 0.0697),
    ('J', 0.0015),
    ('K', 0.0077),
    ('L', 0.0403),
    ('M', 0.0241),
    ('N', 0.0675),
    ('O', 0.0751),
    ('P', 0.0193),
    ('Q', 0.0010),
    ('R', 0.0599),
    ('S', 0.0633),
    ('T', 0.0906),
    ('U', 0.0276),
    ('V', 0.0098),
    ('W', 0.0236),
    ('X', 0.0015),
    ('Y', 0.0197),
    ('Z', 0.0007),
];

pub fn eng_map() -> HashMap<char, f64> {
    LETTER_FREQ.iter().copied().collect()
}
