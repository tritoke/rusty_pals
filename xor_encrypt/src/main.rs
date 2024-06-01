use anyhow::{bail, Context, Result};
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

    /// key to use for encryption
    #[arg(short, long)]
    key: Option<String>,

    /// base64 encoded key
    #[arg(long, conflicts_with = "key")]
    key_b64: Option<String>,
}

fn main() -> Result<()> {
    let args: Args = Args::try_parse()?;

    // evaluate the key
    let key = if let Some(k) = args.key {
        k.into_bytes()
    } else if let Some(kb64) = args.key_b64 {
        kb64.decode_b64()?
    } else {
        bail!("No key was specified for encryption.\nTry setting either --key|--key-b64")
    };

    // read in the input data
    let input = if let Some(input_str) = args.input {
        input_str.into_bytes()
    } else if let Some(ref input_file) = args.input_file {
        fs::read(input_file)
            .with_context(|| format!("Reading from {input_file:?} to get input data."))?
    } else {
        let mut data = vec![];
        io::stdin().read_to_end(&mut data)?;
        data
    };

    // the base64 encoded output
    let enc = xor::xor_with_key(input, key)?.encode_b64();

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

    // write the encrypted output to the file
    out.write_all(&enc.into_bytes())?;

    // if writing to stdout write a newline
    if args.output == "-" {
        out.write_all(b"\n")?;
    }

    Ok(())
}
