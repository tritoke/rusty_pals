use color_eyre::eyre::{eyre, Result};
use rusty_pals::base64::b64decode;
use rusty_pals::edit::edit_distance;
use rusty_pals::ioc::{count_freq, Alphabet};
use rusty_pals::xor::{xor_with_key, xor_with_key_into};

use std::ops::RangeInclusive;

fn main() -> Result<()> {
    color_eyre::install()?;

    let mut input: String = include_str!("../../files/6.txt").to_string();
    input.retain(|c| c != '\n');
    let data = b64decode(input)?;

    let key = break_repeating_key_xor(&data, 2..=40)?;
    print!("Found key: {}", String::from_utf8(key.clone())?);
    let dec = xor_with_key(data, key)?;
    print!("{}", String::from_utf8(dec)?);

    Ok(())
}

fn break_repeating_key_xor(
    data: impl AsRef<[u8]>,
    key_range: RangeInclusive<usize>,
) -> Result<Vec<u8>> {
    const AVERAGE_BLOCKS: usize = 4;
    let data = data.as_ref();
    let mut min_norm = f64::INFINITY;
    let mut best_key_size = 0;
    for key_size in key_range {
        let block1 = data
            .get(..key_size * AVERAGE_BLOCKS)
            .ok_or_else(|| eyre!("input data too small"))?;
        let block2 = data
            .get(key_size * AVERAGE_BLOCKS..key_size * AVERAGE_BLOCKS * 2)
            .ok_or_else(|| eyre!("input data too small"))?;
        let norm = edit_distance(block1, block2) as f64 / key_size as f64;
        if norm < min_norm {
            min_norm = norm;
            best_key_size = key_size;
        }
    }

    let mut key = Vec::new();
    for offset in 0..best_key_size {
        let text: Vec<_> = data
            .iter()
            .skip(offset)
            .step_by(best_key_size)
            .copied()
            .collect();
        key.push(break_single_xor(&text)?);
    }

    Ok(key)
}

fn break_single_xor(data: &[u8]) -> Result<u8> {
    let mut xorred = data.to_vec();
    let mut min_key = 0;
    let mut min_score = f64::INFINITY;
    for key in 1..=u8::MAX {
        xor_with_key_into(&data, [key], &mut xorred)?;
        let score = score_decryption(&xorred);
        if score < min_score {
            min_score = score;
            min_key = key;
        }
    }

    Ok(min_key)
}

fn score_decryption(dec: &[u8]) -> f64 {
    let alphabet = Alphabet::AlphaSpace;
    let counts = count_freq(dec, alphabet);
    counts
        .iter()
        .zip(alphabet.freqs().iter())
        .map(|(a, b)| (a - b).abs())
        .sum()
}
