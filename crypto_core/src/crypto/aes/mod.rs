#![allow(dead_code)]

mod hard;
mod soft;

mod modes;
use std::{arch::x86_64::__m128i, mem};

pub use modes::{CbcMode, CipherMode, CtrMode, EcbMode};

pub const BLOCK_SIZE: usize = 16;
pub type Block = [u8; BLOCK_SIZE];

#[inline(always)]
fn has_hardware_aes_support() -> bool {
    is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2")
}

#[repr(align(16))]
#[derive(Debug, Copy, Clone)]
pub struct AesKey<const R: usize> {
    key_schedule: [[u32; 4]; R],
}

impl<const R: usize> AesKey<R> {
    const fn rk_simd(&self, i: usize) -> __m128i {
        unsafe { mem::transmute::<[u32; 4], __m128i>(self.key_schedule[i]) }
    }
}

/// An expanded AES-128 Key Schedule with 11 round keys
pub type Aes128Key = AesKey<11>;

/// An expanded AES-192 Key Schedule with 13 round keys
pub type Aes192Key = AesKey<13>;

/// An expanded AES-256 Key Schedule with 15 round keys
pub type Aes256Key = AesKey<15>;

impl Aes128Key {
    pub fn new(key: &[u8; 16]) -> Self {
        if has_hardware_aes_support() {
            // SAFETY: we have AES instructions present
            unsafe { hard::aes128_expand_key(key) }
        } else {
            soft::aes128_expand_key(key)
        }
    }
}

impl Aes192Key {
    pub fn new(key: &[u8; 24]) -> Self {
        if has_hardware_aes_support() {
            // SAFETY: we have AES instructions present
            unsafe { hard::aes192_expand_key(key) }
        } else {
            soft::aes192_expand_key(key)
        }
    }
}

impl Aes256Key {
    pub fn new(key: &[u8; 32]) -> Self {
        if has_hardware_aes_support() {
            // SAFETY: we have AES instructions present
            unsafe { hard::aes256_expand_key(key) }
        } else {
            soft::aes256_expand_key(key)
        }
    }
}

pub fn encrypt_block<const R: usize>(
    key_schedule: &AesKey<R>,
    block: &[u8; 16],
    out_block: &mut [u8; 16],
) {
    if has_hardware_aes_support() {
        // SAFETY: we have AES and SSE2 instructions present
        unsafe {
            hard::encrypt_block(key_schedule, block, out_block);
        }
    } else {
        soft::encrypt_block(key_schedule, block, out_block);
    }
}

pub fn decrypt_block<const R: usize>(
    key_schedule: &AesKey<R>,
    block: &[u8; 16],
    out_block: &mut [u8; 16],
) {
    if has_hardware_aes_support() {
        // SAFETY: we have AES and SSE2 instructions present
        unsafe {
            hard::decrypt_block(key_schedule, block, out_block);
        }
    } else {
        soft::decrypt_block(key_schedule, block, out_block);
    }
}

pub struct AesCipher<const R: usize, M>
where
    M: CipherMode<R>,
{
    key_schedule: AesKey<R>,
    mode_state: M,
}

impl<const R: usize, M> AesCipher<R, M>
where
    M: CipherMode<R>,
{
    /// Construct a new AES Cipher parameterised by a key and a cipher mode
    pub fn new(key_schedule: AesKey<R>, mode_state: M) -> Self {
        Self {
            key_schedule,
            mode_state,
        }
    }

    /// Perform AES encryption
    pub fn encrypt_into(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        self.mode_state.encrypt(&self.key_schedule, input, output);
    }

    /// Perform AES encryption
    pub fn encrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; input.as_ref().len()];
        self.encrypt_into(input, &mut out);
        out
    }

    /// Perform AES decryption
    pub fn decrypt_into(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());
        self.mode_state.decrypt(&self.key_schedule, input, output);
    }

    /// Perform AES decryption
    pub fn decrypt(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = input.as_ref().to_vec();
        self.decrypt_into(input, &mut out);
        out
    }
}

/// Tests from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[cfg(test)]
mod nist_tests {
    use super::*;
    use crate::encoding::Decodable;
    use crate::util::cast_as_array;

    fn aes_128_key() -> Aes128Key {
        Aes128Key::new(cast_as_array(
            &"2b7e151628aed2a6abf7158809cf4f3c".decode_hex().unwrap(),
        ))
    }

    fn aes_192_key() -> Aes192Key {
        Aes192Key::new(cast_as_array(
            &"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
                .decode_hex()
                .unwrap(),
        ))
    }

    fn aes_256_key() -> Aes256Key {
        Aes256Key::new(cast_as_array(
            &"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
                .decode_hex()
                .unwrap(),
        ))
    }

    fn plaintext() -> Vec<u8> {
        "6bc1bee22e409f96e93d7e117393172a\
         ae2d8a571e03ac9c9eb76fac45af8e51\
         30c81c46a35ce411e5fbc1191a0a52ef\
         f69f2445df4f9b17ad2b417be66c3710"
            .decode_hex()
            .unwrap()
    }

    #[test]
    fn test_aes_128_ecb_encryption() {
        // NIST test vector F.1.1
        let key = aes_128_key();

        let input = plaintext();
        let correct_output = "3ad77bb40d7a3660a89ecaf32466ef97\
                              f5d3d58503b9699de785895a96fdbaaf\
                              43b1cd7f598ece23881b00e3ed030688\
                              7b0c785e27e8ad3f8223207104725dd4"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, EcbMode()).encrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_128_ecb_decryption() {
        // NIST test vector F.1.2
        let key = aes_128_key();

        let input = "3ad77bb40d7a3660a89ecaf32466ef97\
                     f5d3d58503b9699de785895a96fdbaaf\
                     43b1cd7f598ece23881b00e3ed030688\
                     7b0c785e27e8ad3f8223207104725dd4"
            .decode_hex()
            .unwrap();
        let correct_output = plaintext();

        let output = AesCipher::new(key, EcbMode()).decrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_ecb_encryption() {
        // NIST test vector F.1.3
        let key = aes_192_key();

        let input = plaintext();
        let correct_output = "bd334f1d6e45f25ff712a214571fa5cc\
                              974104846d0ad3ad7734ecb3ecee4eef\
                              ef7afd2270e2e60adce0ba2face6444e\
                              9a4b41ba738d6c72fb16691603c18e0e"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, EcbMode()).encrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_ecb_decryption() {
        // NIST test vector F.1.4
        let key = aes_192_key();

        let input = "bd334f1d6e45f25ff712a214571fa5cc\
                     974104846d0ad3ad7734ecb3ecee4eef\
                     ef7afd2270e2e60adce0ba2face6444e\
                     9a4b41ba738d6c72fb16691603c18e0e"
            .decode_hex()
            .unwrap();
        let correct_output = plaintext();

        let output = AesCipher::new(key, EcbMode()).decrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_ecb_encryption() {
        // NIST test vector F.1.5
        let key = aes_256_key();

        let input = plaintext();
        let correct_output = "f3eed1bdb5d2a03c064b5a7e3db181f8\
                              591ccb10d410ed26dc5ba74a31362870\
                              b6ed21b99ca6f4f9f153e7b1beafed1d\
                              23304b7a39f9f3ff067d8d8f9e24ecc7"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, EcbMode()).encrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_ecb_decryption() {
        // NIST test vector F.1.6
        let key = aes_256_key();

        let input = "f3eed1bdb5d2a03c064b5a7e3db181f8\
                     591ccb10d410ed26dc5ba74a31362870\
                     b6ed21b99ca6f4f9f153e7b1beafed1d\
                     23304b7a39f9f3ff067d8d8f9e24ecc7"
            .decode_hex()
            .unwrap();
        let correct_output = plaintext();

        let output = AesCipher::new(key, EcbMode()).decrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_128_cbc_encryption() {
        // NIST test vector F.2.1
        let key = aes_128_key();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = plaintext();
        let correct_output = "7649abac8119b246cee98e9b12e9197d\
                              5086cb9b507219ee95db113a917678b2\
                              73bed6b8e3c1743b7116e69e22229516\
                              3ff1caa1681fac09120eca307586e1a7"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, CbcMode::new(iv)).encrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_128_cbc_decryption() {
        // NIST test vector F.2.2
        let key = aes_128_key();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = "7649abac8119b246cee98e9b12e9197d\
                     5086cb9b507219ee95db113a917678b2\
                     73bed6b8e3c1743b7116e69e22229516\
                     3ff1caa1681fac09120eca307586e1a7"
            .decode_hex()
            .unwrap();
        let correct_output = plaintext();

        let output = AesCipher::new(key, CbcMode::new(iv)).decrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_cbc_encryption() {
        // NIST test vector F.2.3
        let key = aes_192_key();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = plaintext();
        let correct_output = "4f021db243bc633d7178183a9fa071e8\
                              b4d9ada9ad7dedf4e5e738763f69145a\
                              571b242012fb7ae07fa9baac3df102e0\
                              08b0e27988598881d920a9e64f5615cd"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, CbcMode::new(iv)).encrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_192_cbc_decryption() {
        // NIST test vector F.2.4
        let key = aes_192_key();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let correct_output = plaintext();
        let input = "4f021db243bc633d7178183a9fa071e8\
                     b4d9ada9ad7dedf4e5e738763f69145a\
                     571b242012fb7ae07fa9baac3df102e0\
                     08b0e27988598881d920a9e64f5615cd"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, CbcMode::new(iv)).decrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_cbc_encryption() {
        // NIST test vector F.2.5
        let key = aes_256_key();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let input = plaintext();
        let correct_output = "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                              9cfc4e967edb808d679f777bc6702c7d\
                              39f23369a9d9bacfa530e26304231461\
                              b2eb05e2c39be9fcda6c19078c6a9d1b"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, CbcMode::new(iv)).encrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_256_cbc_decryption() {
        // NIST test vector F.2.6
        let key = aes_256_key();
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let correct_output = plaintext();
        let input = "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                     9cfc4e967edb808d679f777bc6702c7d\
                     39f23369a9d9bacfa530e26304231461\
                     b2eb05e2c39be9fcda6c19078c6a9d1b"
            .decode_hex()
            .unwrap();

        let output = AesCipher::new(key, CbcMode::new(iv)).decrypt(&input);
        assert_eq!(output, correct_output);
    }

    #[test]
    fn test_aes_128_ctr_encryption() {
        // NIST test vector F.5.1
        let key = aes_128_key();

        let input = plaintext();
        let correct_output = "874d6191b620e3261bef6864990db6ce\
                              9806f66b7970fdff8617187bb9fffdff\
                              5ae4df3edbd5d35e5b4f09020db03eab\
                              1e031dda2fbe03d1792170a0f3009cee"
            .decode_hex()
            .unwrap();

        /* NIST and I count differently... */
        let mut ctr = CtrMode::new(0xfffefdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        let mut output = AesCipher::new(key, ctr).encrypt(&input[..BLOCK_SIZE]);
        assert_eq!(output, correct_output[..BLOCK_SIZE]);

        ctr = CtrMode::new(0x00fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[BLOCK_SIZE..2 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[BLOCK_SIZE..2 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x01fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x02fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
    }

    #[test]
    fn test_aes_128_ctr_decryption() {
        // NIST test vector F.5.2
        let key = aes_128_key();

        let correct_output = plaintext();
        let input = "874d6191b620e3261bef6864990db6ce\
                     9806f66b7970fdff8617187bb9fffdff\
                     5ae4df3edbd5d35e5b4f09020db03eab\
                     1e031dda2fbe03d1792170a0f3009cee"
            .decode_hex()
            .unwrap();

        /* NIST and I count differently... */
        let mut ctr = CtrMode::new(0xfffefdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        let mut output = AesCipher::new(key, ctr).decrypt(&input[..BLOCK_SIZE]);
        assert_eq!(output, correct_output[..BLOCK_SIZE]);

        ctr = CtrMode::new(0x00fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[BLOCK_SIZE..2 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[BLOCK_SIZE..2 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x01fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x02fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
    }

    #[test]
    fn test_aes_192_ctr_encryption() {
        // NIST test vector F.5.3
        let key = aes_192_key();

        let input = plaintext();
        let correct_output = "1abc932417521ca24f2b0459fe7e6e0b\
                              090339ec0aa6faefd5ccc2c6f4ce8e94\
                              1e36b26bd1ebc670d1bd1d665620abf7\
                              4f78a7f6d29809585a97daec58c6b050"
            .decode_hex()
            .unwrap();

        /* NIST and I count differently... */
        let mut ctr = CtrMode::new(0xfffefdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        let mut output = AesCipher::new(key, ctr).encrypt(&input[..BLOCK_SIZE]);
        assert_eq!(output, correct_output[..BLOCK_SIZE]);

        ctr = CtrMode::new(0x00fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[BLOCK_SIZE..2 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[BLOCK_SIZE..2 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x01fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x02fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
    }

    #[test]
    fn test_aes_192_ctr_decryption() {
        // NIST test vector F.5.4
        let key = aes_192_key();

        let correct_output = plaintext();
        let input = "1abc932417521ca24f2b0459fe7e6e0b\
                     090339ec0aa6faefd5ccc2c6f4ce8e94\
                     1e36b26bd1ebc670d1bd1d665620abf7\
                     4f78a7f6d29809585a97daec58c6b050"
            .decode_hex()
            .unwrap();

        /* NIST and I count differently... */
        let mut ctr = CtrMode::new(0xfffefdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        let mut output = AesCipher::new(key, ctr).decrypt(&input[..BLOCK_SIZE]);
        assert_eq!(output, correct_output[..BLOCK_SIZE]);

        ctr = CtrMode::new(0x00fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[BLOCK_SIZE..2 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[BLOCK_SIZE..2 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x01fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x02fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
    }

    #[test]
    fn test_aes_256_ctr_encryption() {
        // NIST test vector F.5.3
        let key = aes_256_key();

        let input = plaintext();
        let correct_output = "601ec313775789a5b7a7f504bbf3d228\
                              f443e3ca4d62b59aca84e990cacaf5c5\
                              2b0930daa23de94ce87017ba2d84988d\
                              dfc9c58db67aada613c2dd08457941a6"
            .decode_hex()
            .unwrap();

        /* NIST and I count differently... */
        let mut ctr = CtrMode::new(0xfffefdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        let mut output = AesCipher::new(key, ctr).encrypt(&input[..BLOCK_SIZE]);
        assert_eq!(output, correct_output[..BLOCK_SIZE]);

        ctr = CtrMode::new(0x00fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[BLOCK_SIZE..2 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[BLOCK_SIZE..2 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x01fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x02fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).encrypt(&input[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
    }

    #[test]
    fn test_aes_256_ctr_decryption() {
        // NIST test vector F.5.4
        let key = aes_256_key();

        let correct_output = plaintext();
        let input = "601ec313775789a5b7a7f504bbf3d228\
                     f443e3ca4d62b59aca84e990cacaf5c5\
                     2b0930daa23de94ce87017ba2d84988d\
                     dfc9c58db67aada613c2dd08457941a6"
            .decode_hex()
            .unwrap();

        /* NIST and I count differently... */
        let mut ctr = CtrMode::new(0xfffefdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        let mut output = AesCipher::new(key, ctr).decrypt(&input[..BLOCK_SIZE]);
        assert_eq!(output, correct_output[..BLOCK_SIZE]);

        ctr = CtrMode::new(0x00fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[BLOCK_SIZE..2 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[BLOCK_SIZE..2 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x01fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[2 * BLOCK_SIZE..3 * BLOCK_SIZE]);

        ctr = CtrMode::new(0x02fffdfcfbfaf9f8);
        ctr.seek(0xf7f6f5f4f3f2f1f0 << 4);
        output = AesCipher::new(key, ctr).decrypt(&input[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
        assert_eq!(output, correct_output[3 * BLOCK_SIZE..4 * BLOCK_SIZE]);
    }
}
