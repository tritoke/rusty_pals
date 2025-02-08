use crate::util::{cast_as_arrays, cast_as_arrays_mut};
use crate::xor::{xor_block_simd, xor_block_simd_into};
use std::mem;

use super::{decrypt_block, encrypt_block, AesKey};

pub trait CipherMode<const R: usize> {
    fn encrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]);
    fn decrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]);
}

#[derive(Debug, Default, Copy, Clone)]
pub struct EcbMode();

impl EcbMode {
    pub fn new() -> Self {
        Default::default()
    }
}

impl<const R: usize> CipherMode<R> for EcbMode {
    fn encrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]) {
        let ib = cast_as_arrays(input);
        let ob = cast_as_arrays_mut(output);
        for (block, out_block) in ib.iter().zip(ob.iter_mut()) {
            encrypt_block(key, block, out_block);
        }
    }

    fn decrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]) {
        let ib = cast_as_arrays(input);
        let ob = cast_as_arrays_mut(output);
        for (block, out_block) in ib.iter().zip(ob.iter_mut()) {
            decrypt_block(key, block, out_block);
        }
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct CbcMode {
    iv: super::Block,
}

impl CbcMode {
    pub fn new(iv: super::Block) -> Self {
        Self { iv }
    }
}

impl<const R: usize> CipherMode<R> for CbcMode {
    fn encrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]) {
        let ib = cast_as_arrays(input);
        let ob = cast_as_arrays_mut(output);

        let state = &mut self.iv;
        for (block, out_block) in ib.iter().zip(ob) {
            let input = xor_block_simd(block, state);
            encrypt_block(key, &input, out_block);
            *state = *out_block;
        }
    }

    fn decrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]) {
        let ib = cast_as_arrays(input);
        let ob = cast_as_arrays_mut(output);

        let state = &mut self.iv;
        for (block, out_block) in ib.iter().zip(ob) {
            decrypt_block(key, block, out_block);
            xor_block_simd_into(state, out_block);
            *state = *block;
        }
    }
}

// don't reorder my fields I stg
#[repr(packed)]
#[derive(Debug, Copy, Clone)]
struct Counter {
    block: u64,
    nonce: u64,
}

impl Counter {
    fn new(nonce: u64) -> Self {
        Self { nonce, block: 0 }
    }

    fn as_block(&self) -> super::Block {
        // SAFETY: uhh, repr(packed) (lmao)
        unsafe { mem::transmute(*self) }
    }

    fn seek(&mut self, block_no: u64) {
        self.block = block_no;
    }

    fn step(&mut self, by: u64) {
        self.block = self.block.wrapping_add(by);
    }
}

struct CtrKeystream<'a, const R: usize> {
    counter: Counter,
    key_schedule: &'a AesKey<R>,
    curr_block: super::Block,
    byte_pos: u8,
}

impl<'a, const R: usize> CtrKeystream<'a, R> {
    fn new(key_schedule: &'a AesKey<R>, nonce: u64) -> Self {
        Self {
            counter: Counter::new(nonce),
            key_schedule,
            curr_block: Default::default(),
            byte_pos: 0,
        }
    }

    fn seek(&mut self, byte_pos: u128) {
        const BS: u128 = super::BLOCK_SIZE as u128;
        self.byte_pos = (byte_pos % BS) as u8;

        let block_no = u64::try_from(byte_pos / BS).expect("Attempt to seek across nonces");
        self.counter.seek(block_no);

        // generate a block if we are in the middle of it
        if self.byte_pos != 0 {
            super::encrypt_block(
                self.key_schedule,
                &self.counter.as_block(),
                &mut self.curr_block,
            );
        }
    }
}

impl<const R: usize> Iterator for CtrKeystream<'_, R> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        // if we are at the first byte in the block then generate it
        if self.byte_pos == 0 {
            super::encrypt_block(
                self.key_schedule,
                &self.counter.as_block(),
                &mut self.curr_block,
            );
        }

        let keystream_byte = self.curr_block[self.byte_pos as usize];

        // if after generating a byte we are in the next one step the counter by 1
        self.byte_pos = (self.byte_pos + 1) % super::BLOCK_SIZE as u8;
        if self.byte_pos == 0 {
            self.counter.step(1);
        }

        Some(keystream_byte)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct CtrMode {
    counter_nonce: u64,
    keystream_position: u128,
}

impl CtrMode {
    pub fn new(nonce: u64) -> Self {
        Self {
            counter_nonce: nonce,
            keystream_position: 0,
        }
    }

    pub fn seek(&mut self, pos: u128) {
        self.keystream_position = pos;
    }
}

impl<const R: usize> CipherMode<R> for CtrMode {
    fn encrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]) {
        let mut keystream = CtrKeystream::new(key, self.counter_nonce);
        keystream.seek(self.keystream_position);

        for (k, (i, o)) in keystream.zip(input.iter().zip(output)) {
            *o = i ^ k;
        }
    }

    fn decrypt(&mut self, key: &AesKey<R>, input: &[u8], output: &mut [u8]) {
        self.encrypt(key, input, output);
    }
}
