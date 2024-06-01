use anyhow::{Context, Result};
use clap::Parser;
use crypto_core::encoding::{Decodable, Encodable};
use crypto_core::xor;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// base64 encoded string to brute force the xor decryption of
    #[arg(short, long)]
    input: Option<String>,

    /// the file to read input from, must be raw bytes, not base64 encoded
    ///
    /// the program will read from stdin if neither input-file or input are set
    #[arg(long, conflicts_with = "input")]
    input_file: Option<PathBuf>,

    /// file to write the output to, -o=- => stdout
    #[arg(short, long, default_value_t = String::from("output.txt"))]
    output: String,

    /// force writing to the output file, even if it already exists
    #[arg(short, long, default_value_t = false)]
    force: bool,

    /// minimum length of key to try
    #[arg(long, default_value_t = 2)]
    min_key_length: usize,

    /// max length of key to try
    #[arg(long, default_value_t = 40)]
    max_key_length: usize,

    /// the number of blocks to average over when doing hamming weight computation
    #[arg(short, long, default_value_t = 4)]
    average_blocks: usize,
}

fn main() -> Result<()> {
    let mut args: Args = Args::try_parse()?;

    // read in the encrypted input
    let enc = if let Some(input_str) = args.input {
        input_str.decode_b64()?
    } else if let Some(input_file) = args.input_file {
        fs::read(input_file)?
    } else {
        let mut data = vec![];
        io::stdin().read_to_end(&mut data)?;
        data
    };

    // calculate the actual max key length to ensure we don't overflow
    let true_max_key_len = enc.len() / (args.average_blocks * 2);
    if args.max_key_length > true_max_key_len {
        eprintln!("max key length ({}) was too long for the given input and average blocks ({}), shortening to {true_max_key_len}", args.max_key_length, args.average_blocks);
        args.max_key_length = true_max_key_len;
    }

    // break the repeating key xor
    let key = xor::break_repeating_key_xor(
        &enc,
        args.min_key_length..=args.max_key_length,
        args.average_blocks,
    )?;
    eprintln!(
        "Decrypting using key={}, UTF8={:?}",
        key.encode_hex(),
        std::str::from_utf8(&key)
    );
    let dec = xor::xor_with_key(enc, key)?;

    // choose whether to write to stdout or to a file
    let mut out: Box<dyn Write> = match args.output.as_str() {
        "-" => Box::new(std::io::stdout()),
        fname => Box::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .create_new(!args.force)
                .open(fname)
                .with_context(|| format!("Opening {fname:?} for writing output."))?,
        ),
    };

    // write the decrypted output to the file
    out.write_all(&dec)?;

    // if writing to stdout and not ending with a newline, write a newline
    if args.output == "-" && dec.last() != Some(&b'\n') {
        out.write_all(b"\n")?;
    }

    Ok(())
}
