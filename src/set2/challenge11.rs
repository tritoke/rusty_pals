use color_eyre::eyre::Result;
use openssl::symm::{encrypt, Cipher};
use rusty_pals::hex::to_hex;
use rusty_pals::rand::XorShift32;
use std::collections::HashSet;

fn main() -> Result<()> {
    color_eyre::install()?;

    let mut count_correct = 0;
    let num_rounds = 100;
    let mut rng = XorShift32::new(42)?;
    for _ in 0..num_rounds {
        let (is_ecb, encrypted) = encryption_oracle(
            &mut rng,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )?;
        let is_ecb_guess = detect_mode(encrypted);
        count_correct += (is_ecb == is_ecb_guess) as usize;
    }

    println!("Guessed {count_correct} out of {num_rounds} correct.");
    Ok(())
}

fn encryption_oracle(rng: &mut XorShift32, input: impl AsRef<[u8]>) -> Result<(bool, Vec<u8>)> {
    let n_before = 5 + (rng.gen() % 5) as usize;
    let n_after = 5 + (rng.gen() % 5) as usize;
    let mut data = rng.gen_bytes(n_before);
    data.extend_from_slice(input.as_ref());
    data.extend_from_slice(&rng.gen_bytes(n_after));

    let key = rng.gen_bytes(16);
    let gen_ecb = rng.gen_bool();
    let enc = if gen_ecb {
        encrypt(Cipher::aes_128_ecb(), &key, None, &data)?
    } else {
        let iv = rng.gen_bytes(16);
        encrypt(Cipher::aes_128_cbc(), &key, Some(&iv), &data)?
    };

    Ok((gen_ecb, enc))
}

fn detect_mode(enc: Vec<u8>) -> bool {
    let chunks: Vec<_> = enc.chunks_exact(16).collect();
    let unique_chunks: HashSet<_> = chunks.iter().copied().collect();
    chunks.len() != unique_chunks.len()
}
