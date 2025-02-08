use core::mem;

use super::{Aes128Key, Aes192Key, Aes256Key, AesKey, Block};
use crate::ct::select_u8;

mod constants {
    use super::{gmul, sbox};

    /// Adapted from Sam Trenholme's generate_tables C function:
    /// https://www.samiam.org/galois.html
    const LOG_TABLES: ([u8; 256], [u8; 256]) = {
        let mut atable = [0_u8; 256];
        let mut ltable = [0_u8; 256];

        let mut c = 0;
        let mut a = 1;
        let mut d;
        while c < 255 {
            atable[c] = a;
            /* *= 3 */
            d = a & 0x80;
            a <<= 1;
            if d == 0x80 {
                a ^= 0x1b;
            }
            a ^= atable[c];
            ltable[atable[c] as usize] = c as u8;

            c += 1;
        }

        atable[255] = atable[0];
        ltable[0] = 0;

        (atable, ltable)
    };

    pub const ATABLE: [u8; 256] = LOG_TABLES.0;
    pub const LTABLE: [u8; 256] = LOG_TABLES.1;

    pub const SBOX: [u8; 256] = {
        let mut values = [0; 256];
        let mut i = 0;
        while i < 256 {
            values[i] = sbox(i as u8);
            i += 1;
        }
        values
    };

    pub const INV_SBOX: [u8; 256] = {
        let mut values = [0; 256];
        let mut i = 0;
        while i < 256 {
            values[SBOX[i as usize] as usize] = i as u8;
            i += 1;
        }
        values
    };

    const TE_TABLES: [[u32; 256]; 4] = {
        let mut te0 = [0; 256];
        let mut te1 = [0; 256];
        let mut te2 = [0; 256];
        let mut te3 = [0; 256];

        let mut i = 0;
        while i < 256 {
            let x = SBOX[i];
            let x2 = gmul(x, 2);
            let x3 = gmul(x, 3);

            te0[i] = u32::from_le_bytes([x2, x, x, x3]);
            te1[i] = u32::from_le_bytes([x3, x2, x, x]);
            te2[i] = u32::from_le_bytes([x, x3, x2, x]);
            te3[i] = u32::from_le_bytes([x, x, x3, x2]);

            i += 1;
        }

        [te0, te1, te2, te3]
    };

    pub const TE0: [u32; 256] = TE_TABLES[0];
    pub const TE1: [u32; 256] = TE_TABLES[1];
    pub const TE2: [u32; 256] = TE_TABLES[2];
    pub const TE3: [u32; 256] = TE_TABLES[3];

    const TD_TABLES: [[u32; 256]; 4] = {
        let mut td0 = [0; 256];
        let mut td1 = [0; 256];
        let mut td2 = [0; 256];
        let mut td3 = [0; 256];

        let mut i = 0;
        while i < 256 {
            let x = INV_SBOX[i];
            let x9 = gmul(x, 9);
            let x11 = gmul(x, 11);
            let x13 = gmul(x, 13);
            let x14 = gmul(x, 14);

            td0[i] = u32::from_le_bytes([x14, x9, x13, x11]);
            td1[i] = u32::from_le_bytes([x11, x14, x9, x13]);
            td2[i] = u32::from_le_bytes([x13, x11, x14, x9]);
            td3[i] = u32::from_le_bytes([x9, x13, x11, x14]);

            i += 1;
        }

        [td0, td1, td2, td3]
    };

    pub const TD0: [u32; 256] = TD_TABLES[0];
    pub const TD1: [u32; 256] = TD_TABLES[1];
    pub const TD2: [u32; 256] = TD_TABLES[2];
    pub const TD3: [u32; 256] = TD_TABLES[3];
}

use constants::*;

#[inline(always)]
const fn gadd(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Adapted from https://www.samiam.org/galois.html
const fn gmul(a: u8, b: u8) -> u8 {
    // Cache side channels are a lie to make you write complicated code :p
    let s = LTABLE[a as usize] as u16 + LTABLE[b as usize] as u16;
    let s = ATABLE[(s % 255) as usize];

    // in constant time zero the output if either input was zero
    let s = select_u8(s, 0, a);
    select_u8(s, 0, b)
}

const fn gmul_inverse(a: u8) -> u8 {
    /* 0 is self inverting */
    let inv = ATABLE[(255 - LTABLE[a as usize]) as usize];
    select_u8(inv, 0, a)
}

// Adapted from https://www.samiam.org/s-box.html
const fn sbox(a: u8) -> u8 {
    let s = gmul_inverse(a);
    s ^ s.rotate_left(1) ^ s.rotate_left(2) ^ s.rotate_left(3) ^ s.rotate_left(4) ^ 0x63
}

const fn rcon(mut i: u8) -> u32 {
    let mut rc = 1;
    while i > 1 {
        rc = gmul(rc, 2);
        i -= 1;
    }

    rc as u32
}

#[allow(non_snake_case)]
const fn RotWord(w: u32) -> u32 {
    w.rotate_right(8)
}

#[allow(non_snake_case)]
const fn SubWord(w: u32) -> u32 {
    let [a, b, c, d] = w.to_le_bytes();
    u32::from_le_bytes([
        SBOX[a as usize],
        SBOX[b as usize],
        SBOX[c as usize],
        SBOX[d as usize],
    ])
}

// poor mans [u32; 4 * R]
struct WordArrayWrapper<const R: usize> {
    words: [[u32; 4]; R],
}

impl<const R: usize> WordArrayWrapper<R> {
    const fn new() -> Self {
        Self { words: [[0; 4]; R] }
    }

    const fn index(&self, i: usize) -> u32 {
        self.words[i / 4][i % 4]
    }

    const fn index_mut(&mut self, i: usize) -> &mut u32 {
        &mut self.words[i / 4][i % 4]
    }
}

// Adapted from https://en.wikipedia.org/wiki/AES_key_schedule
#[allow(non_snake_case)]
const fn expand_key<const N: usize, const R: usize>(K: &[u32; N]) -> [[u32; 4]; R] {
    let mut wrapper = WordArrayWrapper::new();
    let mut i = 0;
    while i < 4 * R {
        let word = if i < N {
            K[i]
        } else if i % N == 0 {
            wrapper.index(i - N) ^ SubWord(RotWord(wrapper.index(i - 1))) ^ rcon((i / N) as u8)
        } else if N > 6 && i % N == 4 {
            wrapper.index(i - N) ^ SubWord(wrapper.index(i - 1))
        } else {
            wrapper.index(i - N) ^ wrapper.index(i - 1)
        };

        *wrapper.index_mut(i) = word;

        i += 1;
    }

    wrapper.words
}

#[inline(always)]
pub(super) const fn aes128_expand_key(key: &[u8; 16]) -> Aes128Key {
    #[rustfmt::skip]
    let key_words = [
        u32::from_le_bytes([key[0],  key[1],  key[2],  key[3]]),
        u32::from_le_bytes([key[4],  key[5],  key[6],  key[7]]),
        u32::from_le_bytes([key[8],  key[9],  key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
    ];

    Aes128Key {
        key_schedule: expand_key::<4, 11>(&key_words),
    }
}

#[inline(always)]
pub(super) const fn aes192_expand_key(key: &[u8; 24]) -> Aes192Key {
    #[rustfmt::skip]
    let key_words = [
        u32::from_le_bytes([key[0],  key[1],  key[2],  key[3]]),
        u32::from_le_bytes([key[4],  key[5],  key[6],  key[7]]),
        u32::from_le_bytes([key[8],  key[9],  key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
    ];

    Aes192Key {
        key_schedule: expand_key::<6, 13>(&key_words),
    }
}

#[inline(always)]
pub(super) const fn aes256_expand_key(key: &[u8; 32]) -> Aes256Key {
    #[rustfmt::skip]
    let key_words = [
        u32::from_le_bytes([key[0],  key[1],  key[2],  key[3]]),
        u32::from_le_bytes([key[4],  key[5],  key[6],  key[7]]),
        u32::from_le_bytes([key[8],  key[9],  key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
    ];

    Aes256Key {
        key_schedule: expand_key::<8, 15>(&key_words),
    }
}

/// AES 4x4 state matrix
#[repr(align(16))]
struct State {
    columns: [u32; 4],
}

impl State {
    const fn from_block(block: Block) -> Self {
        unsafe { mem::transmute::<Block, Self>(block) }
    }

    const fn into_block(self) -> Block {
        unsafe { mem::transmute::<Self, Block>(self) }
    }
}

#[allow(non_snake_case)]
const fn AddRoundKey(state: &mut State, key: &[u32; 4]) {
    state.columns[0] ^= key[0];
    state.columns[1] ^= key[1];
    state.columns[2] ^= key[2];
    state.columns[3] ^= key[3];
}

// I can name things weirdly, as a treat :)
#[allow(non_snake_case)]
const fn SubBytesAndShiftRowsAndMixColumns(state: &mut State) {
    let [c0, c1, c2, c3] = &mut state.columns;

    let [s00, s10, s20, s30] = c0.to_le_bytes();
    let [s01, s11, s21, s31] = c1.to_le_bytes();
    let [s02, s12, s22, s32] = c2.to_le_bytes();
    let [s03, s13, s23, s33] = c3.to_le_bytes();

    *c0 = TE0[s00 as usize] ^ TE1[s11 as usize] ^ TE2[s22 as usize] ^ TE3[s33 as usize];
    *c1 = TE0[s01 as usize] ^ TE1[s12 as usize] ^ TE2[s23 as usize] ^ TE3[s30 as usize];
    *c2 = TE0[s02 as usize] ^ TE1[s13 as usize] ^ TE2[s20 as usize] ^ TE3[s31 as usize];
    *c3 = TE0[s03 as usize] ^ TE1[s10 as usize] ^ TE2[s21 as usize] ^ TE3[s32 as usize];
}

// I can name things weirdly, as a treat :)
#[allow(non_snake_case)]
const fn InvSubBytesAndShiftRowsAndMixColumns(state: &mut State) {
    let [c0, c1, c2, c3] = &mut state.columns;

    let [s00, s10, s20, s30] = c0.to_le_bytes();
    let [s01, s11, s21, s31] = c1.to_le_bytes();
    let [s02, s12, s22, s32] = c2.to_le_bytes();
    let [s03, s13, s23, s33] = c3.to_le_bytes();

    *c0 = TD0[s00 as usize] ^ TD1[s13 as usize] ^ TD2[s22 as usize] ^ TD3[s31 as usize];
    *c1 = TD0[s01 as usize] ^ TD1[s10 as usize] ^ TD2[s23 as usize] ^ TD3[s32 as usize];
    *c2 = TD0[s02 as usize] ^ TD1[s11 as usize] ^ TD2[s20 as usize] ^ TD3[s33 as usize];
    *c3 = TD0[s03 as usize] ^ TD1[s12 as usize] ^ TD2[s21 as usize] ^ TD3[s30 as usize];
}

// I can name things weirdly, as a treat :)
#[allow(non_snake_case)]
const fn SubBytesAndShiftRows(state: &mut State) {
    let [c0, c1, c2, c3] = &mut state.columns;

    let [s00, s10, s20, s30] = c0.to_le_bytes();
    let [s01, s11, s21, s31] = c1.to_le_bytes();
    let [s02, s12, s22, s32] = c2.to_le_bytes();
    let [s03, s13, s23, s33] = c3.to_le_bytes();

    *c0 = u32::from_le_bytes([
        SBOX[s00 as usize],
        SBOX[s11 as usize],
        SBOX[s22 as usize],
        SBOX[s33 as usize],
    ]);
    *c1 = u32::from_le_bytes([
        SBOX[s01 as usize],
        SBOX[s12 as usize],
        SBOX[s23 as usize],
        SBOX[s30 as usize],
    ]);
    *c2 = u32::from_le_bytes([
        SBOX[s02 as usize],
        SBOX[s13 as usize],
        SBOX[s20 as usize],
        SBOX[s31 as usize],
    ]);
    *c3 = u32::from_le_bytes([
        SBOX[s03 as usize],
        SBOX[s10 as usize],
        SBOX[s21 as usize],
        SBOX[s32 as usize],
    ]);
}

// I can name things weirdly, as a treat :)
#[allow(non_snake_case)]
const fn InvSubBytesAndShiftRows(state: &mut State) {
    let [c0, c1, c2, c3] = &mut state.columns;

    let [s00, s10, s20, s30] = c0.to_le_bytes();
    let [s01, s11, s21, s31] = c1.to_le_bytes();
    let [s02, s12, s22, s32] = c2.to_le_bytes();
    let [s03, s13, s23, s33] = c3.to_le_bytes();

    *c0 = u32::from_le_bytes([
        INV_SBOX[s00 as usize],
        INV_SBOX[s13 as usize],
        INV_SBOX[s22 as usize],
        INV_SBOX[s31 as usize],
    ]);
    *c1 = u32::from_le_bytes([
        INV_SBOX[s01 as usize],
        INV_SBOX[s10 as usize],
        INV_SBOX[s23 as usize],
        INV_SBOX[s32 as usize],
    ]);
    *c2 = u32::from_le_bytes([
        INV_SBOX[s02 as usize],
        INV_SBOX[s11 as usize],
        INV_SBOX[s20 as usize],
        INV_SBOX[s33 as usize],
    ]);
    *c3 = u32::from_le_bytes([
        INV_SBOX[s03 as usize],
        INV_SBOX[s12 as usize],
        INV_SBOX[s21 as usize],
        INV_SBOX[s30 as usize],
    ]);
}

#[allow(non_snake_case)]
const fn InvMixColumns(mut round_key: [u32; 4]) -> [u32; 4] {
    let mut i = 0;
    while i < 4 {
        let subkey = &mut round_key[i];
        let [k0, k1, k2, k3] = subkey.to_le_bytes();
        *subkey = TD0[SBOX[k0 as usize] as usize]
            ^ TD1[SBOX[k1 as usize] as usize]
            ^ TD2[SBOX[k2 as usize] as usize]
            ^ TD3[SBOX[k3 as usize] as usize];

        i += 1;
    }

    round_key
}

pub(super) const fn encrypt_block<const R: usize>(
    key: &AesKey<R>,
    block: &Block,
    out_block: &mut Block,
) {
    let mut state = State::from_block(*block);
    let mut i = 0;

    AddRoundKey(&mut state, &key.key_schedule[i]);
    i += 1;

    while i < R - 1 {
        SubBytesAndShiftRowsAndMixColumns(&mut state);
        AddRoundKey(&mut state, &key.key_schedule[i]);

        i += 1;
    }

    SubBytesAndShiftRows(&mut state);
    AddRoundKey(&mut state, &key.key_schedule[i]);

    *out_block = state.into_block();
}

pub(super) const fn decrypt_block<const R: usize>(
    key: &AesKey<R>,
    block: &Block,
    out_block: &mut Block,
) {
    let mut state = State::from_block(*block);
    let mut i = R - 1;

    AddRoundKey(&mut state, &key.key_schedule[i]);
    i -= 1;

    while i != 0 {
        InvSubBytesAndShiftRowsAndMixColumns(&mut state);
        AddRoundKey(&mut state, &InvMixColumns(key.key_schedule[i]));

        i -= 1;
    }

    InvSubBytesAndShiftRows(&mut state);
    AddRoundKey(&mut state, &key.key_schedule[i]);

    *out_block = state.into_block();
}

#[cfg(test)]
mod tests {
    use crate::{encoding::Decodable as _, util::cast_as_array};

    use super::*;

    // Also adapted from https://www.samiam.org/galois.html
    fn gmul_slow(mut a: u8, mut b: u8) -> u8 {
        let mut p: u8 = 0;
        for _ in 0..8 {
            if (b & 1) == 1 {
                p ^= a;
            }
            let reduce = (a & 0x80) == 0x80;
            a <<= 1;
            if reduce {
                a ^= 0x1b;
            }
            b >>= 1;
        }

        p
    }

    #[test]
    fn test_gmul() {
        for a in u8::MIN..=u8::MAX {
            for b in u8::MIN..=u8::MAX {
                assert_eq!(gmul(a, b), gmul_slow(a, b));
            }
        }
    }

    #[test]
    fn test_gmul_inverse() {
        assert_eq!(gmul_inverse(0), 0);
        for a in 1..=u8::MAX {
            let inv = gmul_inverse(a);
            assert_eq!(gmul(a, inv), 1);
        }
    }

    #[test]
    fn test_aes_128_key_expansion() {
        let correct: [[u32; 4]; 11] = [
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
            [0x63636362, 0x63636362, 0x63636362, 0x63636362],
            [0xc998989b, 0xaafbfbf9, 0xc998989b, 0xaafbfbf9],
            [0x50349790, 0xfacf6c69, 0x3357f4f2, 0x99ac0f0b],
            [0x7bda06ee, 0x81156a87, 0xb2429e75, 0x2bee917e],
            [0x882b2e7f, 0x093e44f8, 0xbb7cda8d, 0x90924bf3],
            [0x854b61ec, 0x8c752514, 0x3709ff99, 0xa79bb46a],
            [0x87177521, 0x0b625035, 0x3c6bafac, 0x9bf01bc6],
            [0x3303f90e, 0x3861a93b, 0x040a0697, 0x9ffa1d51],
            [0xe2d8d4b1, 0xdab97d8a, 0xdeb37b1d, 0x4149664c],
            [0xcb5befb4, 0x11e2923e, 0xcf51e923, 0x8e188f6f],
        ];

        assert_eq!(aes128_expand_key(&[0; 16]).key_schedule, correct);
    }

    #[test]
    fn test_aes_192_key_expansion() {
        let correct: [[u32; 4]; 13] = [
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
            [0x00000000, 0x00000000, 0x63636362, 0x63636362],
            [0x63636362, 0x63636362, 0x63636362, 0x63636362],
            [0xc998989b, 0xaafbfbf9, 0xc998989b, 0xaafbfbf9],
            [0xc998989b, 0xaafbfbf9, 0x50349790, 0xfacf6c69],
            [0x3357f4f2, 0x99ac0f0b, 0x50349790, 0xfacf6c69],
            [0xa9191dc8, 0x53d671a1, 0x60818553, 0xf92d8a58],
            [0xa9191dc8, 0x53d671a1, 0x9bf4eb7b, 0xc8229ada],
            [0xa8a31f89, 0x518e95d1, 0xf8978819, 0xab41f9b8],
            [0xf79668c2, 0x3fb4f218, 0x9717ed91, 0xc6997840],
            [0x3e0ef059, 0x954f09e1, 0x0fbcec83, 0x30081e9b],
            [0xa71ff30a, 0x61868b4a, 0x5f887b13, 0xcac772f2],
            [0x86c82a43, 0xb6c034d8, 0x11dfc7d2, 0x70594c98],
        ];

        assert_eq!(aes192_expand_key(&[0; 24]).key_schedule, correct);
    }

    #[test]
    fn test_aes_256_key_expansion() {
        let correct: [[u32; 4]; 15] = [
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
            [0x00000000, 0x00000000, 0x00000000, 0x00000000],
            [0x63636362, 0x63636362, 0x63636362, 0x63636362],
            [0xfbfbfbaa, 0xfbfbfbaa, 0xfbfbfbaa, 0xfbfbfbaa],
            [0xcf6c6c6f, 0xac0f0f0d, 0xcf6c6c6f, 0xac0f0f0d],
            [0x6a8d8d7d, 0x917676d7, 0x6a8d8d7d, 0x917676d7],
            [0xc1ed5453, 0x6de25b5e, 0xa28e3731, 0x0e81383c],
            [0xc1818a96, 0x50f7fc41, 0x3a7a713c, 0xab0c07eb],
            [0x288faa9e, 0x456df1c0, 0xe7e3c6f1, 0xe962fecd],
            [0xdf2b312b, 0x8fdccd6a, 0xb5a6bc56, 0x1eaabbbd],
            [0x52fd0664, 0x1790f7a4, 0xf0733155, 0x1911cf98],
            [0x0ba9bb6d, 0x84757607, 0x31d3ca51, 0x2f7971ec],
            [0x9ce8b0e7, 0x8b784743, 0x7b0b7616, 0x621ab98e],
            [0xa10bed74, 0x257e9b73, 0x14ad5122, 0x3bd420ce],
            [0x170af810, 0x9c72bf53, 0xe779c945, 0x856370cb],
        ];

        assert_eq!(aes256_expand_key(&[0; 32]).key_schedule, correct);
    }
}
