use color_eyre::Result;
use rusty_pals::hex::parse_hex;
use rusty_pals::ioc::{count_freq, Alphabet};
use rusty_pals::xor::{xor_with_key, xor_with_key_into};

fn main() -> Result<()> {
    color_eyre::install()?;

    const INPUT: &str = include_str!("../../files/4.txt");
    let data: Vec<Vec<u8>> = INPUT.lines().map(parse_hex).collect::<Result<_>>()?;

    let mut min_score = f64::MAX;
    let mut index = 0;
    let mut key = 0;
    for (i, ct) in data.iter().map(AsRef::as_ref).enumerate() {
        let (k, score) = break_single_xor(&ct)?;
        if score < min_score {
            min_score = score;
            index = i;
            key = k;
        }
    }

    let out = xor_with_key(&data[index], [key])?;
    let dec = String::from_utf8(out)?;
    println!("String {index} decrypts to {dec:?} using key {key}");

    Ok(())
}

fn break_single_xor(data: &[u8]) -> Result<(u8, f64)> {
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

    Ok((min_key, min_score))
}

fn score_decryption(dec: &[u8]) -> f64 {
    let alphabet = Alphabet::AlphaSpace;
    let counts = count_freq(dec, alphabet);
    counts
        .into_iter()
        .zip(alphabet.freqs().into_iter())
        .map(|(a, b)| (a - b).abs())
        .sum()
}
