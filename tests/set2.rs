#![feature(array_chunks)]

extern crate core;

use color_eyre::eyre::Result;
use rusty_pals::encoding::b64decode;
use rusty_pals::encryption::aes::{decrypt, encrypt, Aes, Aes128, Mode};
use rusty_pals::encryption::pad;
use rusty_pals::rand::XorShift32;
use rusty_pals::util::{self, cast_as_array};

#[test]
fn challenge9() -> Result<()> {
    let input = "YELLOW SUBMARINE";
    let padded = pad::pkcs7(input, 20);
    println!("{:?}", padded);
    assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");

    Ok(())
}

#[test]
fn challenge10() -> Result<()> {
    let mut input = include_str!("files/10.txt").to_string();
    input.retain(|c| c != '\n');
    let data = b64decode(input)?;
    let key = Aes128::new(b"YELLOW SUBMARINE");
    let iv = [0u8; 16];
    let mut dec = decrypt(&data, key, Some(&iv), Mode::CBC);
    pad::pkcs7_unpad_owned(&mut dec)?;
    assert_eq!(dec, include_bytes!("files/10_correct.txt"));

    Ok(())
}

#[test]
fn challenge11() -> Result<()> {
    fn encryption_oracle(rng: &mut XorShift32, input: impl AsRef<[u8]>) -> Result<(bool, Vec<u8>)> {
        let n_before = 5 + (rng.gen() % 5) as usize;
        let n_after = 5 + (rng.gen() % 5) as usize;
        let mut data = rng.gen_bytes(n_before);
        data.extend_from_slice(input.as_ref());
        data.extend_from_slice(&rng.gen_bytes(n_after));
        pad::pkcs7_into(&mut data, Aes128::BLOCK_SIZE as u8);

        let key = Aes128::new(&rng.gen_array());
        let gen_ecb = rng.gen_bool();
        let enc = if gen_ecb {
            encrypt(&data, key, None, Mode::ECB)
        } else {
            let iv = rng.gen_array();
            encrypt(&data, key, Some(&iv), Mode::CBC)
        };

        Ok((gen_ecb, enc))
    }

    /// Detect the cipher mode by encrypting data which has at least 2 consecutive blocks with identical data.
    /// We can construct an input like this by passing a long run of the same data to the oracle.
    /// For ECB mode this will result in two consecutive blocks which encrypt to the same value.
    /// Whereas for CBC mode these blocks will encrypt differently due to the XOR operation mixing the bits.
    fn detect_mode(enc: Vec<u8>) -> bool {
        let blocks: &[[u8; 16]] = cast_as_array(enc.as_slice());
        util::has_duplicate(blocks)
    }

    let mut count_correct = 0;
    let num_rounds = 10000;
    let mut rng = XorShift32::new(42)?;
    for _ in 0..num_rounds {
        let (is_ecb, encrypted) = encryption_oracle(&mut rng, "a".repeat(43))?;
        let is_ecb_guess = detect_mode(encrypted);
        count_correct += (is_ecb == is_ecb_guess) as usize;
    }

    assert_eq!(count_correct, num_rounds);

    Ok(())
}
