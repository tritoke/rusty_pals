use color_eyre::Result;
use rusty_pals::hex::{parse_hex, to_hex};
use rusty_pals::xor::xor_blocks;

fn main() -> Result<()> {
    color_eyre::install()?;

    const INPUT1: &str = "1c0111001f010100061a024b53535009181c";
    const INPUT2: &str = "686974207468652062756c6c277320657965";

    let a = parse_hex(INPUT1)?;
    let b = parse_hex(INPUT2)?;
    let output = to_hex(&xor_blocks(a, b)?);

    println!("{}", output);

    assert_eq!(output, "746865206B696420646F6E277420706C6179");

    Ok(())
}
