use crate::crypto::Hasher;
use std::mem;
use std::num::Wrapping;

pub mod constants {
    pub const WORD_A: u32 = u32::from_le_bytes([0x01, 0x23, 0x45, 0x67]);
    pub const WORD_B: u32 = u32::from_le_bytes([0x89, 0xab, 0xcd, 0xef]);
    pub const WORD_C: u32 = u32::from_le_bytes([0xfe, 0xdc, 0xba, 0x98]);
    pub const WORD_D: u32 = u32::from_le_bytes([0x76, 0x54, 0x32, 0x10]);
}
use crate::encoding::Encodable;
use crate::util::as_chunks;
use constants::*;

#[derive(Debug, Clone)]
pub struct Md4 {
    state: [Wrapping<u32>; 4],
    message_length: u64,
    unprocessed_data: Vec<u8>,
    finalized: bool,
}

/// Wrapper around [u8; 20] which ensures it has sufficient alignment
/// to be cast between [u32; 5] and [u8; 20]
#[repr(align(4))]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Digest(pub [u8; 16]);

impl Encodable for Digest {
    fn encode_hex(&self) -> String {
        self.0.encode_hex()
    }

    fn encode_b64(&self) -> String {
        self.0.encode_b64()
    }
}

impl From<[Wrapping<u32>; 4]> for Digest {
    fn from(state: [Wrapping<u32>; 4]) -> Self {
        // Safety: u32 can always be safely cast into u8's
        Self(unsafe { mem::transmute(state.map(|w| w.0)) })
    }
}

impl From<Digest> for [Wrapping<u32>; 4] {
    fn from(digest: Digest) -> Self {
        // Safety: the struct guarantees 4 byte alignment, thus it is always safe to transmute
        // back from [u8] to [u32]
        unsafe { mem::transmute::<_, [u32; 4]>(digest) }.map(Wrapping)
    }
}

impl Md4 {
    #[allow(non_snake_case)]
    #[rustfmt::skip]
    unsafe fn process_block(&mut self, block: &[u8; 64]) {
        let X: [Wrapping<u32>; 16] = mem::transmute(*block);

        let [mut a, mut b, mut c, mut d] = self.state;

        // F(X,Y,Z) = XY v not(X) Z
        macro_rules! F {
            ($x:ident, $y:ident, $z: ident) => {
                ($x & $y) | (!$x & $z)
            };
        }

        // G(X,Y,Z) = XY v XZ v YZ
        macro_rules! G {
            ($x:ident, $y:ident, $z: ident) => {
                ($x & $y) | ($x & $z) | ($y & $z)
            };
        }

        // H(X,Y,Z) = X xor Y xor Z
        macro_rules! H {
            ($x:ident, $y:ident, $z: ident) => {
                $x ^ $y ^ $z
            };
        }

        /* Round 1. */
        /* Let [abcd k s] denote the operation
        a = (a + F(b,c,d) + X[k]) <<< s. */
        macro_rules! r1 {
            ($a:ident $b:ident $c:ident $d:ident $k:literal $s: literal) => {
                $a = Wrapping(($a + F!($b, $c, $d) + X[$k]).0.rotate_left($s));
            };
        }

        /* Do the following 16 operations. */
        r1!(a b c d  0  3); r1!(d a b c  1  7); r1!(c d a b  2 11); r1!(b c d a  3 19);
        r1!(a b c d  4  3); r1!(d a b c  5  7); r1!(c d a b  6 11); r1!(b c d a  7 19);
        r1!(a b c d  8  3); r1!(d a b c  9  7); r1!(c d a b 10 11); r1!(b c d a 11 19);
        r1!(a b c d 12  3); r1!(d a b c 13  7); r1!(c d a b 14 11); r1!(b c d a 15 19);

        /* Round 2. */
        /* Let [abcd k s] denote the operation
        a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. */
        macro_rules! r2 {
            ($a:ident $b:ident $c:ident $d:ident $k:literal $s: literal) => {
                $a = Wrapping(($a + G!($b, $c, $d) + X[$k] + Wrapping(0x5A827999)).0.rotate_left($s));
            };
        }

        /* Do the following 16 operations. */
        r2!(a b c d  0  3); r2!(d a b c  4  5); r2!(c d a b  8  9); r2!(b c d a 12 13);
        r2!(a b c d  1  3); r2!(d a b c  5  5); r2!(c d a b  9  9); r2!(b c d a 13 13);
        r2!(a b c d  2  3); r2!(d a b c  6  5); r2!(c d a b 10  9); r2!(b c d a 14 13);
        r2!(a b c d  3  3); r2!(d a b c  7  5); r2!(c d a b 11  9); r2!(b c d a 15 13);

        /* Round 3. */
        /* Let [abcd k s] denote the operation
        a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s. */
        macro_rules! r3 {
            ($a:ident $b:ident $c:ident $d:ident $k:literal $s: literal) => {
                $a = Wrapping(($a + H!($b, $c, $d) + X[$k] + Wrapping(0x6ED9EBA1)).0.rotate_left($s));
            };
        }

        /* Do the following 16 operations. */
        r3!(a b c d  0  3); r3!(d a b c  8  9); r3!(c d a b  4 11); r3!(b c d a 12 15);
        r3!(a b c d  2  3); r3!(d a b c 10  9); r3!(c d a b  6 11); r3!(b c d a 14 15);
        r3!(a b c d  1  3); r3!(d a b c  9  9); r3!(c d a b  5 11); r3!(b c d a 13 15);
        r3!(a b c d  3  3); r3!(d a b c 11  9); r3!(c d a b  7 11); r3!(b c d a 15 15);

        /* Then perform the following additions. (That is, increment each
        of the four registers by the value it had before this block
        was started.) */

        self.state[0] += a;
        self.state[1] += b;
        self.state[2] += c;
        self.state[3] += d;
        self.message_length += 512;
    }
}

impl Hasher for Md4 {
    type Digest = Digest;

    fn new() -> Self {
        Self {
            state: [WORD_A, WORD_B, WORD_C, WORD_D].map(Wrapping),
            message_length: 0,
            unprocessed_data: Vec::new(),
            finalized: false,
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        assert!(!self.finalized, "Cannot update a finalized Hasher.");

        self.unprocessed_data.extend_from_slice(data.as_ref());
        let data = mem::take(&mut self.unprocessed_data);
        let (blocks, remaining) = as_chunks(&data);
        for block in blocks {
            unsafe { self.process_block(block) };
        }
        self.unprocessed_data.extend_from_slice(remaining);
    }

    fn finalize(&mut self) {
        self.message_length += self.unprocessed_data.len() as u64 * 8;

        self.unprocessed_data.push(0x80);
        let k = (-(self.message_length as i64) - 64 - 8).rem_euclid(512);
        self.unprocessed_data
            .extend_from_slice(&vec![0; k as usize / 8]);
        self.unprocessed_data
            .extend_from_slice(&self.message_length.to_le_bytes());

        self.update("");
        self.finalized = true;

        assert!(
            self.unprocessed_data.is_empty(),
            "There must be no unprocessed data after finalization."
        );
    }

    fn digest(&self) -> Self::Digest {
        assert!(
            self.finalized,
            "Attempting to get the digest of an unfinalized Hasher."
        );
        self.state.into()
    }

    fn reset(&mut self) {
        self.state = [WORD_A, WORD_B, WORD_C, WORD_D].map(Wrapping);
        self.message_length = 0;
        self.unprocessed_data = Vec::new();
        self.finalized = false;
    }
}

impl From<<Md4 as Hasher>::Digest> for Md4 {
    fn from(digest: <Md4 as Hasher>::Digest) -> Self {
        Self {
            state: digest.into(),
            message_length: 0,
            unprocessed_data: Vec::new(),
            finalized: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Encodable;

    // test vectors from https://www.rfc-editor.org/rfc/rfc1320
    #[test]
    fn test_md4_rfc_vectors() {
        let test_vectors = [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        let mut hasher = Md4::new();
        for (test, correct) in test_vectors {
            hasher.update(test);
            hasher.finalize();
            let hash = hasher.digest();
            assert_eq!(hash.encode_hex(), correct);
            hasher.reset();
        }
    }

    #[test]
    fn test_md4_to_from_digest() {
        let mut hasher = Md4::new();
        hasher.update("Wow this string sure isn't very long.");
        hasher.finalize();
        let recovered: Md4 = hasher.digest().into();
        assert_eq!(hasher.state, recovered.state)
    }

    #[test]
    fn test_md4_digest_is_le() {
        let digest: Digest = [1, 2, 3, 4].map(Wrapping).into();
        let repr = [1, 2, 3, 4].map(u32::to_le_bytes).concat();
        assert_eq!(&digest.0[..], &repr[..]);
    }

    #[test]
    fn test_md4_digest_to_state() {
        let digest0: Digest = [5, 4, 3, 2].map(Wrapping).into();
        let digest1: [Wrapping<u32>; 4] = digest0.into();
        let digest2: Digest = digest1.into();
        assert_eq!(digest0, digest2);
    }
}
