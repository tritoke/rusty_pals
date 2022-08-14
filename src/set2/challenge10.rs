#![feature(array_chunks)]

use color_eyre::eyre::{ensure, eyre, Result};
use rusty_pals::base64::b64decode;
use rusty_pals::pad::{pkcs7, pkcs7_unpad};
use rusty_pals::xor::xor_blocks_together;

use openssl::symm::{Cipher, Crypter, Mode};

fn main() -> Result<()> {
    color_eyre::install()?;

    let message = "SUBMARINEYELLOW";
    let key = b"YELLOW SUBMARINE";
    let iv = [b'a'; 16];
    let data = cbc_encrypt(message, &iv, key)?;
    let dec = cbc_decrypt(&data, &iv, key)?;
    let s = String::from_utf8(dec)?;

    assert_eq!(s, message);

    let mut input = include_str!("../../files/10.txt").to_string();
    input.retain(|c| c != '\n');
    let data = b64decode(input)?;
    let iv = [0u8; 16];
    let dec = cbc_decrypt(&data, &iv, key)?;
    print!("{}", String::from_utf8(dec).unwrap());

    Ok(())
}

fn cbc_decrypt(data: &[u8], iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();
    let block_size = cipher.block_size();
    ensure!(
        data.len() % block_size == 0,
        "Encrypted data must be a multiple of the block size: {block_size}."
    );
    ensure!(
        iv.len() == block_size,
        "IV must be {block_size} bytes long."
    );

    let mut dec = vec![0u8; data.len() + block_size];
    let mut count = 0;
    let mut prev_block = iv;
    for block in data.chunks(block_size) {
        let mut decryptor = Crypter::new(cipher, Mode::Decrypt, key, None)?;
        decryptor.update(
            block,
            dec.get_mut(count..)
                .ok_or_else(|| eyre!("Ran out of output space."))?,
        )?;
        xor_blocks_together(prev_block, &mut dec[count..count + block_size])?;
        count += block_size;
        prev_block = block;
    }

    dec.truncate(count);
    pkcs7_unpad(&dec).map(Vec::from)
}

fn cbc_encrypt(data: impl AsRef<[u8]>, iv: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Cipher::aes_128_ecb();
    let block_size = cipher.block_size();
    ensure!(
        iv.len() == block_size,
        "IV must be {block_size} bytes long."
    );

    // pad the data
    let mut data = pkcs7(data, block_size as u8);

    // encrypt block by block, XORing in the previous block
    let mut enc = vec![0u8; data.len() + block_size];
    let mut count = 0;
    let mut prev_block = iv.to_vec();
    for block in data.chunks_mut(block_size) {
        let mut encryptor = Crypter::new(cipher, Mode::Encrypt, key, None)?;
        xor_blocks_together(&prev_block, block)?;
        encryptor.update(
            block,
            enc.get_mut(count..)
                .ok_or_else(|| eyre!("Ran out of output space."))?,
        )?;
        count += block_size;
        prev_block.copy_from_slice(block);
    }

    enc.truncate(count);
    Ok(enc)
}
