use color_eyre::eyre::Result;
use rusty_pals::pad;

fn main() -> Result<()> {
    color_eyre::install()?;

    let input = "YELLOW SUBMARINE";
    let padded = pad::pkcs7(input, 20);
    println!("{:?}", padded);
    assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");

    Ok(())
}
