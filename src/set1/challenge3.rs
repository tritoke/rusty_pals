use color_eyre::Result;
use rusty_pals::hex::parse_hex;
use rusty_pals::ioc::{count_freq, Alphabet};
use rusty_pals::xor::xor_with_key_into;

fn main() -> Result<()> {
    color_eyre::install()?;

    const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let data = parse_hex(INPUT)?;
    let mut xorred = data.clone();

    let mut min_key = 0;
    let mut min_score = f64::MAX;
    for key in 1..=u8::MAX {
        xor_with_key_into(&data, [key], &mut xorred)?;
        let score = score_decryption(&xorred);
        if score < min_score {
            min_score = score;
            min_key = key;
        }
    }

    xor_with_key_into(&data, [min_key], &mut xorred)?;
    let out = String::from_utf8(xorred)?;
    println!("{}", out);

    Ok(())
}

fn score_decryption(dec: &[u8]) -> f64 {
    let alphabet = Alphabet::Alpha;
    let counts = count_freq(dec, Alphabet::Alpha);
    counts
        .into_iter()
        .zip(alphabet.freqs().iter())
        .map(|(a, b)| (a - b).abs())
        .sum()
}
