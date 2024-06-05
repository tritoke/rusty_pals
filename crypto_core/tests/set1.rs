use crypto_core::crypto::aes::*;
use crypto_core::crypto::pad::*;
use crypto_core::encoding::*;
use crypto_core::fit::*;
use crypto_core::xor::*;

use crypto_core::util;
use crypto_core::util::cast_as_arrays;

mod helpers;
use helpers::*;

#[derive(Debug, Copy, Clone)]
pub enum ChallengeError {
    DecodingError(DecodingError),
    XorError(XorError),
    PaddingError(PaddingError),
}

impl_error_boilerplate!(ChallengeError);
impl_error_from_types!(ChallengeError: DecodingError, XorError, PaddingError);

pub type ChallengeResult<T> = Result<T, ChallengeError>;

#[test]
fn challenge1() -> ChallengeResult<()> {
    const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    assert_eq!(
        INPUT.decode_hex()?.encode_b64(),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    Ok(())
}

#[test]
fn challenge2() -> ChallengeResult<()> {
    const INPUT1: &str = "1c0111001f010100061a024b53535009181c";
    const INPUT2: &str = "686974207468652062756c6c277320657965";

    let a = INPUT1.decode_hex()?;
    let b = INPUT2.decode_hex()?;
    let output = &xor_blocks(a, b)?.encode_hex();

    assert_eq!(output, "746865206b696420646f6e277420706c6179");

    Ok(())
}

#[test]
fn challenge3() -> ChallengeResult<()> {
    const INPUT: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let data = INPUT.decode_hex()?;

    let key = break_single_xor(&data)?;
    let xorred = xor_with_key(data, [key])?;
    assert_eq!(xorred, b"Cooking MC's like a pound of bacon");

    Ok(())
}

#[test]
fn challenge4() -> ChallengeResult<()> {
    const INPUT: &str = include_str!("files/4.txt");
    let data: Vec<Vec<u8>> = INPUT
        .lines()
        .map(Decodable::decode_hex)
        .collect::<Result<_, _>>()?;

    let plain = data
        .iter()
        .map::<ChallengeResult<_>, _>(|ct| {
            let k = break_single_xor(ct)?;
            Ok(xor_with_key(ct, [k])?)
        })
        .filter_map(Result::ok)
        .max_by_key(|text| score_text(text))
        .unwrap();

    assert_eq!(plain, b"Now that the party is jumping\n");

    Ok(())
}

#[test]
fn challenge5() -> ChallengeResult<()> {
    const INPUT: &str = "\
        Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal\
    ";

    assert_eq!(
        xor_with_key(INPUT, "ICE")?.encode_hex(),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
        a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );

    Ok(())
}

#[test]
fn challenge6() -> ChallengeResult<()> {
    let mut input: String = include_str!("files/6.txt").to_string();
    input.retain(|c| c != '\n');
    let data = b64decode(input)?;

    let key = break_repeating_key_xor(data, 2..=40, 4)?;
    assert_eq!(key, b"Terminator X: Bring the noise");

    Ok(())
}

#[test]
fn challenge7() -> ChallengeResult<()> {
    let mut input = include_str!("files/7.txt").to_string();
    input.retain(|c| c != '\n');
    let data = b64decode(input)?;
    let key = Aes128::new(b"YELLOW SUBMARINE");
    let dec = decrypt(data, key, Iv::Empty, Mode::ECB);
    let unpad = pkcs7_unpad(&dec[..])?;

    assert_eq!(unpad, include_bytes!("files/7_correct.txt"));

    Ok(())
}

#[test]
fn challenge8() -> ChallengeResult<()> {
    let lines: Vec<Vec<u8>> = include_str!("files/8.txt")
        .lines()
        .map(parse_hex)
        .collect::<Result<_, DecodingError>>()?;

    let prob_ecb = lines
        .iter()
        .find(|line| util::has_duplicate(cast_as_arrays::<_, 16>(line)))
        .expect("Couldn't find line with duplicate blocks.");

    assert_eq!(prob_ecb, &lines[132]);

    Ok(())
}
