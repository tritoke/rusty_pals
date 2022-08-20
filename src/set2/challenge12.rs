#![feature(once_cell)]

use color_eyre::eyre::{ensure, eyre, Result};
use openssl::symm::{encrypt, Cipher};
use rusty_pals::base64::b64decode;
use rusty_pals::hex::to_hex;
use rusty_pals::oracle::EncryptionOracle;
use rusty_pals::rand::XorShift32;
use tracing::{instrument, trace};

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    color_eyre::install()?;

    let mut rng = XorShift32::new(42)?;
    let oracle = EcbOracle::new(&mut rng)?;

    let decoded = attack(oracle)?;
    print!("{}", std::str::from_utf8(&decoded)?);

    Ok(())
}

#[instrument]
fn attack(oracle: impl EncryptionOracle + fmt::Debug) -> Result<Vec<u8>> {
    // Step 1. find the block size
    // we can feeding the cipher longer and longer strings until the length
    // of the returned ciphertext is becomes longer
    let empty_len = oracle.encrypt("")?.len();
    let mut i = 1;
    let block_size = loop {
        let l = oracle.encrypt("a".repeat(i))?.len();
        if l != empty_len {
            break l - empty_len;
        }
        i += 1;
    };

    // Step 2: Detect the cipher mode
    // out input is of the form user-string || secret, so we can provide a string of 2*block_size
    // bytes to get two identical blocks at the beginning
    let enc = oracle.encrypt("a".repeat(2 * block_size))?;
    ensure!(
        &enc[0..16] == &enc[16..32],
        "Oracle is not using the ECB encryption mode."
    );

    // Step 3/4: craft the block mappings
    let mut prefix_mapper = PrefixMapper::new(block_size);
    let mut prefix = VecDeque::from(vec![b'A'; block_size - 1]);
    prefix_mapper.compute_mappings(prefix.make_contiguous(), &oracle)?;

    // Step 5: Match the output of the one-byte-short input
    let enc = oracle.encrypt(prefix.as_slices().0)?;
    let block = &enc[..block_size];
    let decoded = prefix_mapper
        .get(block)
        .ok_or_else(|| eyre!("Failed to recover byte from secret."))?;

    // Step 6: Repeat :)
    let mut dec = vec![decoded];
    // for i in 1..empty_len {
    //     prefix.pop_front();
    //     prefix.push_back(dec.last().copied().unwrap());
    //     prefix_mapper.compute_mappings(prefix.make_contiguous(), &oracle)?;

    //     let block_offset = i / 16;
    //     let enc = oracle.encrypt(prefix.as_slices().0)?;
    //     let block = &enc[block_offset * block_size..(block_offset + 1) * block_size];
    //     let decoded = prefix_mapper
    //         .get(block)
    //         .ok_or_else(|| eyre!("Failed to recovery byte from secret."))?;
    //     dec.push(decoded);
    // }

    Ok(dec)
}

/// Struct representing an Oracle performing AES-ECB-128 Encryption
#[derive(Debug)]
struct EcbOracle {
    key: Vec<u8>,
    secret: Vec<u8>,
}

impl EcbOracle {
    fn new(rng: &mut XorShift32) -> Result<Self> {
        let secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK";
        let secret = b64decode(secret_b64)?;
        let key = rng.gen_bytes(16);
        Ok(Self { key, secret })
    }
}

impl EncryptionOracle for EcbOracle {
    fn encrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut data = data.as_ref().to_vec();
        // Construct your-string || unknown-string
        data.extend_from_slice(&self.secret);

        // Construct ECB(your-string || unknown-string, random-key)
        encrypt(Cipher::aes_128_ecb(), &self.key, None, &data).map_err(|e| eyre!(e))
    }
}

/// A struct storing the mappings for all the prefixes, ensuring they are only calculated once
#[derive(Default)]
struct PrefixMapper {
    mapping: HashMap<Vec<u8>, u8>,
    prefixes: HashSet<Vec<u8>>,
    block_size: usize,
}

impl PrefixMapper {
    fn new(block_size: usize) -> Self {
        Self {
            block_size,
            ..Default::default()
        }
    }

    /// Compute the mappings for a given prefix
    fn compute_mappings(&mut self, prefix: &[u8], oracle: &impl EncryptionOracle) -> Result<()> {
        ensure!(
            prefix.len() == self.block_size - 1,
            "Prefixes must be one byte less than the block size - {}",
            self.block_size - 1
        );

        // check wether we have already calculated these prefixes
        if self.prefixes.insert(prefix.to_vec()) {
            return Ok(());
        }

        let mut prefix = prefix.to_vec();
        prefix.push(0);
        for b in u8::MIN..=u8::MAX {
            prefix[15] = b;
            let enc = oracle.encrypt(&prefix)?;
            let block = dbg!(enc[0..self.block_size].to_vec());
            trace!("b = {b}, block = {}", to_hex(&block));
            self.mapping.insert(block, b);
        }

        Ok(())
    }

    /// Get elements from the mapping
    fn get(&self, block: &[u8]) -> Option<u8> {
        self.mapping.get(block).copied()
    }
}
