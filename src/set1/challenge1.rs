use color_eyre::Result;
use rusty_pals::base64::b64encode;
use rusty_pals::hex::parse_hex;

fn main() -> Result<()> {
    color_eyre::install()?;

    const INPUT: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let hex_bytes = parse_hex(INPUT)?;
    let output = b64encode(hex_bytes);

    println!("{}", output);

    assert_eq!(
        output,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    Ok(())
}
