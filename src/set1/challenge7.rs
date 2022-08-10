use color_eyre::eyre::{eyre, Result};
use rusty_pals::base64::b64decode;

use openssl::symm::{decrypt, Cipher};

fn main() -> Result<()> {
    color_eyre::install()?;

    let mut input = include_str!("../../files/6.txt").to_string();
    input.retain(|c| c != '\n');
    let data = b64decode(input)?;
    let key = b"YELLOW SUBMARINE";

    let cipher = Cipher::aes_128_ecb();
    let dec = decrypt(cipher, key, None, &data)?;
    print!("{}", String::from_utf8(dec)?);
    Ok(())
}
