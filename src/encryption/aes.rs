#![allow(dead_code)]

use crate::util::{cast_as_array, cast_as_array_mut};
use crate::xor::{xor_block_simd, xor_block_simd_into};
use std::arch::x86_64::*;

#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Mode {
    /// Electronic Cookbook
    ECB,
    /// Cipher Block Chaining
    CBC,
    /// Cipher Feedback mode
    CFB,
    /// Output Feedback mode
    OFB,
    /// Counter mode
    CTR,
}

/// Helpers derived from https://www.intel.com/content/dam/develop/external/us/en/documents/aes-wp-2012-09-22-v01-165683.pdf
mod helpers {
    use std::arch::x86_64::*;
    use std::{array, mem, ptr};

    unsafe fn aes_128_assist(mut t1: __m128i, mut t2: __m128i) -> __m128i {
        let mut t3: __m128i;
        t2 = _mm_shuffle_epi32::<0xFF>(t2);
        t3 = _mm_slli_si128::<0x4>(t1);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128::<0x4>(t3);
        t1 = _mm_xor_si128(t1, t3);
        t3 = _mm_slli_si128::<0x4>(t3);
        t1 = _mm_xor_si128(t1, t3);
        t1 = _mm_xor_si128(t1, t2);
        t1
    }

    pub unsafe fn aes_128_key_expansion(key: [u8; 16]) -> [__m128i; 11] {
        let mut t1: __m128i;
        let mut t2: __m128i;
        let mut key_schedule = array::from_fn(|_| unsafe { _mm_setzero_si128() });

        t1 = _mm_loadu_si128(&key as *const u8 as *const _);
        key_schedule[0] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x1>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[1] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x2>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[2] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x4>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[3] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x8>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[4] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x10>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[5] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x20>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[6] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x40>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[7] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x80>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[8] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x1b>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[9] = t1;

        t2 = _mm_aeskeygenassist_si128::<0x36>(t1);
        t1 = aes_128_assist(t1, t2);
        key_schedule[10] = t1;

        key_schedule
    }

    #[rustfmt::skip]
    unsafe fn aes_192_assist(t1: &mut __m128i, t2: &mut __m128i, t3: &mut __m128i) {
        let mut t4: __m128i;
        *t2 = _mm_shuffle_epi32::<0x55>(*t2);
        t4  = _mm_slli_si128::<0x4>(*t1);
        *t1 = _mm_xor_si128(*t1, t4);
        t4  = _mm_slli_si128::<0x4>(t4);
        *t1 = _mm_xor_si128(*t1, t4);
        t4  = _mm_slli_si128::<0x4>(t4);
        *t1 = _mm_xor_si128(*t1, t4);
        *t1 = _mm_xor_si128(*t1, *t2);
        *t2 = _mm_shuffle_epi32::<0xff>(*t1);
        t4  = _mm_slli_si128::<0x4>(*t3);
        *t3 = _mm_xor_si128(*t3, t4);
        *t3 = _mm_xor_si128(*t3, *t2);
    }

    #[rustfmt::skip]
    pub unsafe fn aes_192_key_expansion(key: [u8; 24]) -> [__m128i; 13] {
        #[inline]
        unsafe fn shuffle<const MASK: i32>(a: __m128i, b: __m128i) -> __m128i {
            mem::transmute(_mm_shuffle_pd::<MASK>(mem::transmute(a), mem::transmute(b)))
        }

        let mut t2: __m128i;
        let mut key_schedule = array::from_fn(|_| unsafe { _mm_setzero_si128() });

        let (mut t1, mut t3) = {
            // prevent OOB read
            let mut mem = [0u8; 32];
            ptr::write(mem.as_mut_ptr() as *mut _, key);

            (
                _mm_loadu_si128(mem.as_ptr() as *const _),
                _mm_loadu_si128(mem.as_ptr().offset(16) as *const _)
            )
        };

        key_schedule[0] = t1;
        key_schedule[1] = t3;
        t2 = _mm_aeskeygenassist_si128::<0x1>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[1] = shuffle::<0>(key_schedule[1], t1);
        key_schedule[2] = shuffle::<1>(t1, t3);

        t2 = _mm_aeskeygenassist_si128::<0x2>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[3] = t1;
        key_schedule[4] = t3;
        t2 = _mm_aeskeygenassist_si128::<0x4>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[4] = shuffle::<0>(key_schedule[4], t1);
        key_schedule[5] = shuffle::<1>(t1, t3);

        t2 = _mm_aeskeygenassist_si128::<0x8>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[6] = t1;
        key_schedule[7] = t3;
        t2 = _mm_aeskeygenassist_si128::<0x10>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[7] = shuffle::<0>(key_schedule[7], t1);
        key_schedule[8] = shuffle::<1>(t1, t3);

        t2 = _mm_aeskeygenassist_si128::<0x20>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[9] = t1;
        key_schedule[10] = t3;
        t2 = _mm_aeskeygenassist_si128::<0x40>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[10] = shuffle::<0>(key_schedule[10], t1);
        key_schedule[11] = shuffle::<1>(t1, t3);

        t2 = _mm_aeskeygenassist_si128::<0x80>(t3);
        aes_192_assist(&mut t1, &mut t2, &mut t3);
        key_schedule[12] = t1;

        key_schedule
    }

    #[rustfmt::skip]
    unsafe fn aes_256_assist_1(t1: &mut __m128i, t2: &mut __m128i) {
        let mut t4: __m128i;
        *t2 = _mm_shuffle_epi32::<0xFF>(*t2);
        t4  = _mm_slli_si128::<0x4>(*t1);
        *t1 = _mm_xor_si128(*t1, t4);
        t4  = _mm_slli_si128::<0x4>(t4);
        *t1 = _mm_xor_si128(*t1, t4);
        t4  = _mm_slli_si128::<0x4>(t4);
        *t1 = _mm_xor_si128(*t1, t4);
        *t1 = _mm_xor_si128(*t1, *t2);
    }

    #[rustfmt::skip]
    unsafe fn aes_256_assist_2(t1: &mut __m128i, t3: &mut __m128i) {
        let t2: __m128i;
        let mut t4: __m128i;
        t4  = _mm_aeskeygenassist_si128::<0x0>(*t1);
        t2  = _mm_shuffle_epi32::<0xaa>(t4);
        t4  = _mm_slli_si128::<0x4>(*t3);
        *t3 = _mm_xor_si128(*t3, t4);
        t4  = _mm_slli_si128::<0x4>(t4);
        *t3 = _mm_xor_si128(*t3, t4);
        t4  = _mm_slli_si128::<0x4>(t4);
        *t3 = _mm_xor_si128(*t3, t4);
        *t3 = _mm_xor_si128(*t3, t2);
    }

    pub unsafe fn aes_256_key_expansion(key: [u8; 32]) -> [__m128i; 15] {
        let mut t1: __m128i;
        let mut t2: __m128i;
        let mut t3: __m128i;
        let mut key_schedule = array::from_fn(|_| unsafe { _mm_setzero_si128() });

        t1 = _mm_loadu_si128(key.as_ptr() as *const _);
        t3 = _mm_loadu_si128(key.as_ptr().offset(16) as *const _);
        key_schedule[0] = t1;
        key_schedule[1] = t3;

        t2 = _mm_aeskeygenassist_si128::<0x01>(t3);
        aes_256_assist_1(&mut t1, &mut t2);
        key_schedule[2] = t1;
        aes_256_assist_2(&mut t1, &mut t3);
        key_schedule[3] = t3;

        t2 = _mm_aeskeygenassist_si128::<0x02>(t3);
        aes_256_assist_1(&mut t1, &mut t2);
        key_schedule[4] = t1;
        aes_256_assist_2(&mut t1, &mut t3);
        key_schedule[5] = t3;

        t2 = _mm_aeskeygenassist_si128::<0x04>(t3);
        aes_256_assist_1(&mut t1, &mut t2);
        key_schedule[6] = t1;
        aes_256_assist_2(&mut t1, &mut t3);
        key_schedule[7] = t3;

        t2 = _mm_aeskeygenassist_si128::<0x08>(t3);
        aes_256_assist_1(&mut t1, &mut t2);
        key_schedule[8] = t1;
        aes_256_assist_2(&mut t1, &mut t3);
        key_schedule[9] = t3;

        t2 = _mm_aeskeygenassist_si128::<0x10>(t3);
        aes_256_assist_1(&mut t1, &mut t2);
        key_schedule[10] = t1;
        aes_256_assist_2(&mut t1, &mut t3);
        key_schedule[11] = t3;

        t2 = _mm_aeskeygenassist_si128::<0x20>(t3);
        aes_256_assist_1(&mut t1, &mut t2);
        key_schedule[12] = t1;
        aes_256_assist_2(&mut t1, &mut t3);
        key_schedule[13] = t3;

        t2 = _mm_aeskeygenassist_si128::<0x40>(t3);
        aes_256_assist_1(&mut t1, &mut t2);
        key_schedule[14] = t1;

        key_schedule
    }
}

pub trait AesKeySchedule {
    const ROUNDS: usize;
    fn round_key(&self, round: usize) -> __m128i;
}

#[derive(Debug, Copy, Clone)]
pub struct Aes128 {
    key_schedule: [__m128i; 11],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            key_schedule: unsafe { helpers::aes_128_key_expansion(*key) },
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Aes192 {
    key_schedule: [__m128i; 13],
}

impl Aes192 {
    fn new(key: &[u8; 24]) -> Self {
        Self {
            key_schedule: unsafe { helpers::aes_192_key_expansion(*key) },
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Aes256 {
    key_schedule: [__m128i; 15],
}

impl Aes256 {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            key_schedule: unsafe { helpers::aes_256_key_expansion(*key) },
        }
    }
}

macro_rules! impl_aes_key_schedule {
    ( $t:ty, $rounds:literal ) => {
        impl AesKeySchedule for $t {
            const ROUNDS: usize = $rounds;

            fn round_key(&self, round: usize) -> __m128i {
                self.key_schedule[round]
            }
        }
    };
}
impl_aes_key_schedule!(Aes128, 10);
impl_aes_key_schedule!(Aes192, 12);
impl_aes_key_schedule!(Aes256, 14);

pub trait Aes {
    const BLOCK_SIZE: usize = 16;
    fn encrypt_block(&self, block: &[u8; 16], out_block: &mut [u8; 16]);
    fn decrypt_block(&self, block: &[u8; 16], out_block: &mut [u8; 16]);
}

impl<T> Aes for T
where
    T: AesKeySchedule,
{
    fn encrypt_block(&self, block: &[u8; 16], out_block: &mut [u8; 16]) {
        let mut t = unsafe { _mm_loadu_si128(block as *const u8 as *const _) };
        t = unsafe { _mm_xor_si128(t, self.round_key(0)) };
        for round in 1..T::ROUNDS {
            t = unsafe { _mm_aesenc_si128(t, self.round_key(round)) };
        }
        t = unsafe { _mm_aesenclast_si128(t, self.round_key(T::ROUNDS)) };
        unsafe { _mm_storeu_si128(out_block as *mut u8 as *mut _, t) };
    }

    fn decrypt_block(&self, block: &[u8; 16], out_block: &mut [u8; 16]) {
        let mut t = unsafe { _mm_loadu_si128(block as *const u8 as *const _) };
        t = unsafe { _mm_xor_si128(t, self.round_key(T::ROUNDS)) };
        for round in (1..T::ROUNDS).rev() {
            t = unsafe { _mm_aesdec_si128(t, _mm_aesimc_si128(self.round_key(round))) };
        }
        t = unsafe { _mm_aesdeclast_si128(t, self.round_key(0)) };
        unsafe { _mm_storeu_si128(out_block as *mut u8 as *mut _, t) };
    }
}

/// Perform encryption using AES ECB mode
fn encrypt_ecb(input: &[[u8; 16]], out: &mut [[u8; 16]], aes: impl Aes) {
    for (block, out_block) in input.iter().zip(out.iter_mut()) {
        aes.encrypt_block(block, out_block);
    }
}

/// Perform encryption using AES CBC mode
fn encrypt_cbc(input: &[[u8; 16]], out: &mut [[u8; 16]], iv: &[u8; 16], aes: impl Aes) {
    let mut state = *iv;
    for (block, out_block) in input.iter().zip(out.iter_mut()) {
        let input = xor_block_simd(block, &state);
        aes.encrypt_block(&input, out_block);
        state = *out_block;
    }
}

/// Perform AES encryption
pub fn encrypt(
    input: impl AsRef<[u8]>,
    key: impl AesKeySchedule,
    iv: Option<&[u8; 16]>,
    mode: Mode,
) -> Vec<u8> {
    let mut out = input.as_ref().to_vec();
    match mode {
        Mode::ECB => encrypt_ecb(
            cast_as_array(input.as_ref()),
            cast_as_array_mut(&mut out[..]),
            key,
        ),
        Mode::CBC => encrypt_cbc(
            cast_as_array(input.as_ref()),
            cast_as_array_mut(&mut out[..]),
            iv.expect("CBC mode requires an IV."),
            key,
        ),
        Mode::OFB | Mode::CFB | Mode::CTR => unimplemented!(),
    };
    out
}

/// Perform decryption using AES ECB mode
fn decrypt_ecb(input: &[[u8; 16]], out: &mut [[u8; 16]], aes: impl Aes) {
    for (block, out_block) in input.iter().zip(out.iter_mut()) {
        aes.decrypt_block(block, out_block);
    }
}

/// Perform decryption using AES CBC mode
fn decrypt_cbc(input: &[[u8; 16]], out: &mut [[u8; 16]], iv: &[u8; 16], aes: impl Aes) {
    let mut state = *iv;
    for (block, out_block) in input.iter().zip(out.iter_mut()) {
        aes.decrypt_block(block, out_block);
        xor_block_simd_into(&state, out_block);
        state = *block;
    }
}

/// Perform AES encryption
/// Panics: if mode == CBC and iv.is_none()
pub fn decrypt(
    input: impl AsRef<[u8]>,
    key: impl AesKeySchedule,
    iv: Option<&[u8; 16]>,
    mode: Mode,
) -> Vec<u8> {
    let mut out = input.as_ref().to_vec();
    match mode {
        Mode::ECB => decrypt_ecb(
            cast_as_array(input.as_ref()),
            cast_as_array_mut(&mut out[..]),
            key,
        ),
        Mode::CBC => decrypt_cbc(
            cast_as_array(input.as_ref()),
            cast_as_array_mut(&mut out[..]),
            iv.expect("CBC mode requires an IV."),
            key,
        ),
        Mode::OFB | Mode::CFB | Mode::CTR => unimplemented!(),
    };
    out
}

/// Tests from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[cfg(test)]
mod nist_tests {
    use super::*;
    use crate::encoding::Decodable;
    use crate::util::cast_as_array;

    #[test]
    fn test_aes_128_ecb_encryption() {
        // NIST test vector F.1.1
        let key = "2b7e151628aed2a6abf7158809cf4f3c".decode_hex().unwrap();
        let key = Aes128::new(&cast_as_array(&key[..])[0]);

        let input = "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52ef\
                     f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let correct_output = "3ad77bb40d7a3660a89ecaf32466ef97\
                              f5d3d58503b9699de785895a96fdbaaf\
                              43b1cd7f598ece23881b00e3ed030688\
                              7b0c785e27e8ad3f8223207104725dd4"
            .decode_hex()
            .unwrap();

        let output = encrypt(input, key, None, Mode::ECB);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_128_ecb_decryption() {
        // NIST test vector F.1.2
        let key = "2b7e151628aed2a6abf7158809cf4f3c".decode_hex().unwrap();
        let key = Aes128::new(&cast_as_array(&key[..])[0]);

        let input = "3ad77bb40d7a3660a89ecaf32466ef97\
                     f5d3d58503b9699de785895a96fdbaaf\
                     43b1cd7f598ece23881b00e3ed030688\
                     7b0c785e27e8ad3f8223207104725dd4"
            .decode_hex()
            .unwrap();
        let correct_output = "6bc1bee22e409f96e93d7e117393172a\
                              ae2d8a571e03ac9c9eb76fac45af8e51\
                              30c81c46a35ce411e5fbc1191a0a52ef\
                              f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();

        let output = decrypt(input, key, None, Mode::ECB);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_ecb_encryption() {
        // NIST test vector F.1.3
        let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
            .decode_hex()
            .unwrap();
        let key = Aes192::new(&cast_as_array(&key[..])[0]);

        let input = "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52ef\
                     f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let correct_output = "bd334f1d6e45f25ff712a214571fa5cc\
                              974104846d0ad3ad7734ecb3ecee4eef\
                              ef7afd2270e2e60adce0ba2face6444e\
                              9a4b41ba738d6c72fb16691603c18e0e"
            .decode_hex()
            .unwrap();

        let output = encrypt(input, key, None, Mode::ECB);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_ecb_decryption() {
        // NIST test vector F.1.4
        let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
            .decode_hex()
            .unwrap();
        let key = Aes192::new(&cast_as_array(&key[..])[0]);

        let input = "bd334f1d6e45f25ff712a214571fa5cc\
                     974104846d0ad3ad7734ecb3ecee4eef\
                     ef7afd2270e2e60adce0ba2face6444e\
                     9a4b41ba738d6c72fb16691603c18e0e"
            .decode_hex()
            .unwrap();
        let correct_output = "6bc1bee22e409f96e93d7e117393172a\
                              ae2d8a571e03ac9c9eb76fac45af8e51\
                              30c81c46a35ce411e5fbc1191a0a52ef\
                              f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();

        let output = decrypt(input, key, None, Mode::ECB);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_ecb_encryption() {
        // NIST test vector F.1.5
        let key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
            .decode_hex()
            .unwrap();
        let key = Aes256::new(&cast_as_array(&key[..])[0]);

        let input = "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52ef\
                     f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let correct_output = "f3eed1bdb5d2a03c064b5a7e3db181f8\
                              591ccb10d410ed26dc5ba74a31362870\
                              b6ed21b99ca6f4f9f153e7b1beafed1d\
                              23304b7a39f9f3ff067d8d8f9e24ecc7"
            .decode_hex()
            .unwrap();

        let output = encrypt(input, key, None, Mode::ECB);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_ecb_decryption() {
        // NIST test vector F.1.6
        let key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
            .decode_hex()
            .unwrap();
        let key = Aes256::new(&cast_as_array(&key[..])[0]);

        let input = "f3eed1bdb5d2a03c064b5a7e3db181f8\
                     591ccb10d410ed26dc5ba74a31362870\
                     b6ed21b99ca6f4f9f153e7b1beafed1d\
                     23304b7a39f9f3ff067d8d8f9e24ecc7"
            .decode_hex()
            .unwrap();
        let correct_output = "6bc1bee22e409f96e93d7e117393172a\
                              ae2d8a571e03ac9c9eb76fac45af8e51\
                              30c81c46a35ce411e5fbc1191a0a52ef\
                              f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();

        let output = decrypt(input, key, None, Mode::ECB);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_128_cbc_encryption() {
        // NIST test vector F.2.1
        let key = "2b7e151628aed2a6abf7158809cf4f3c".decode_hex().unwrap();
        let key = Aes128::new(&cast_as_array(&key[..])[0]);
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52ef\
                     f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let correct_output = "7649abac8119b246cee98e9b12e9197d\
                              5086cb9b507219ee95db113a917678b2\
                              73bed6b8e3c1743b7116e69e22229516\
                              3ff1caa1681fac09120eca307586e1a7"
            .decode_hex()
            .unwrap();

        let output = encrypt(input, key, Some(&iv), Mode::CBC);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_128_cbc_decryption() {
        // NIST test vector F.2.2
        let key = "2b7e151628aed2a6abf7158809cf4f3c".decode_hex().unwrap();
        let key = Aes128::new(&cast_as_array(&key[..])[0]);
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = "7649abac8119b246cee98e9b12e9197d\
                     5086cb9b507219ee95db113a917678b2\
                     73bed6b8e3c1743b7116e69e22229516\
                     3ff1caa1681fac09120eca307586e1a7"
            .decode_hex()
            .unwrap();
        let correct_output = "6bc1bee22e409f96e93d7e117393172a\
                              ae2d8a571e03ac9c9eb76fac45af8e51\
                              30c81c46a35ce411e5fbc1191a0a52ef\
                              f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();

        let output = decrypt(input, key, Some(&iv), Mode::CBC);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_cbc_encryption() {
        // NIST test vector F.1.3
        let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
            .decode_hex()
            .unwrap();
        let key = Aes192::new(&cast_as_array(&key[..])[0]);
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52ef\
                     f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let correct_output = "4f021db243bc633d7178183a9fa071e8\
                              b4d9ada9ad7dedf4e5e738763f69145a\
                              571b242012fb7ae07fa9baac3df102e0\
                              08b0e27988598881d920a9e64f5615cd"
            .decode_hex()
            .unwrap();

        let output = encrypt(input, key, Some(&iv), Mode::CBC);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_cbc_decryption() {
        // NIST test vector F.1.4
        let key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
            .decode_hex()
            .unwrap();
        let key = Aes192::new(&cast_as_array(&key[..])[0]);
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let correct_output = "6bc1bee22e409f96e93d7e117393172a\
                              ae2d8a571e03ac9c9eb76fac45af8e51\
                              30c81c46a35ce411e5fbc1191a0a52ef\
                              f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let input = "4f021db243bc633d7178183a9fa071e8\
                     b4d9ada9ad7dedf4e5e738763f69145a\
                     571b242012fb7ae07fa9baac3df102e0\
                     08b0e27988598881d920a9e64f5615cd"
            .decode_hex()
            .unwrap();

        let output = decrypt(input, key, Some(&iv), Mode::CBC);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_cbc_encryption() {
        // NIST test vector F.1.5
        let key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
            .decode_hex()
            .unwrap();
        let key = Aes256::new(&cast_as_array(&key[..])[0]);
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = "6bc1bee22e409f96e93d7e117393172a\
                     ae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52ef\
                     f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let correct_output = "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                              9cfc4e967edb808d679f777bc6702c7d\
                              39f23369a9d9bacfa530e26304231461\
                              b2eb05e2c39be9fcda6c19078c6a9d1b"
            .decode_hex()
            .unwrap();

        let output = encrypt(input, key, Some(&iv), Mode::CBC);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_cbc_decryption() {
        // NIST test vector F.1.6
        let key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
            .decode_hex()
            .unwrap();
        let key = Aes256::new(&cast_as_array(&key[..])[0]);
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let correct_output = "6bc1bee22e409f96e93d7e117393172a\
                              ae2d8a571e03ac9c9eb76fac45af8e51\
                              30c81c46a35ce411e5fbc1191a0a52ef\
                              f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap();
        let input = "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                     9cfc4e967edb808d679f777bc6702c7d\
                     39f23369a9d9bacfa530e26304231461\
                     b2eb05e2c39be9fcda6c19078c6a9d1b"
            .decode_hex()
            .unwrap();

        let output = decrypt(input, key, Some(&iv), Mode::CBC);
        assert_eq!(output, correct_output);
    }
}
