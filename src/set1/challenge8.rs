#![feature(array_chunks)]

use std::collections::HashSet;

use color_eyre::eyre::{eyre, Result};
use rusty_pals::base64::b64decode;

use rusty_pals::hex;

fn main() -> Result<()> {
    color_eyre::install()?;

    let lines: Vec<Vec<u8>> = include_str!("../../files/8.txt")
        .lines()
        .map(hex::parse_hex)
        .collect::<Result<_>>()?;

    let prob_ecb = lines
        .into_iter()
        .find(|line| {
            let unique_blocks: HashSet<_> = line.array_chunks::<16>().collect();
            unique_blocks.len() != (line.len() / 16)
        })
        .ok_or_else(|| eyre!("Couldn't find line with duplicate blocks."))?;

    print!("{}", hex::to_hex(prob_ecb.as_slice()));

    Ok(())
}
