///! SHA2 implemented as per FIPS 180-4: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
use std::mem;

use crate::crypto::Hasher;
use crate::encoding::Encodable;
use crate::util::{as_chunks, cast_as_arrays};

macro_rules! Ch {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) ^ (!$x & $z)
    };
}

macro_rules! Maj {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) ^ ($x & $z) ^ ($y & $z)
    };
}

macro_rules! Parity {
    ($x:expr, $y:expr, $z:expr) => {
        $x ^ $y ^ $z
    };
}

mod context {
    mod sha224_sha256_shared {
        #[rustfmt::skip]
        pub const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];

        #[allow(non_snake_case)]
        pub const fn Σ_0(x: u32) -> u32 {
            x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
        }

        #[allow(non_snake_case)]
        pub const fn Σ_1(x: u32) -> u32 {
            x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
        }

        pub const fn σ_0(x: u32) -> u32 {
            x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
        }

        pub const fn σ_1(x: u32) -> u32 {
            x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
        }

        pub const BLOCK_SIZE: usize = 64;
        pub const ROUNDS: usize = 64;
        pub type Word = u32;
        pub type MessageLength = u64;
    }

    mod sha384_sha512_shared {
        #[rustfmt::skip]
        pub const K: [u64; 80] = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        ];

        #[allow(non_snake_case)]
        pub const fn Σ_0(x: u64) -> u64 {
            x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
        }

        #[allow(non_snake_case)]
        pub const fn Σ_1(x: u64) -> u64 {
            x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
        }

        pub const fn σ_0(x: u64) -> u64 {
            x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
        }

        pub const fn σ_1(x: u64) -> u64 {
            x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
        }

        pub const BLOCK_SIZE: usize = 128;
        pub const ROUNDS: usize = 80;
        pub type Word = u64;
        pub type MessageLength = u128;
    }

    pub mod sha1 {
        const H0: u32 = 0x67452301;
        const H1: u32 = 0xEFCDAB89;
        const H2: u32 = 0x98BADCFE;
        const H3: u32 = 0x10325476;
        const H4: u32 = 0xC3D2E1F0;

        pub const INIT_STATE: [Word; STATE_SIZE] = [H0, H1, H2, H3, H4];

        pub const STATE_SIZE: usize = 5;
        pub const DIGEST_SIZE: usize = 5;
        pub const ROUNDS: usize = 80;
        pub const BLOCK_SIZE: usize = 64;

        pub const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

        pub type Word = u32;
        pub type MessageLength = u64;
    }

    pub mod sha224 {
        const H0: u32 = 0xc1059ed8;
        const H1: u32 = 0x367cd507;
        const H2: u32 = 0x3070dd17;
        const H3: u32 = 0xf70e5939;
        const H4: u32 = 0xffc00b31;
        const H5: u32 = 0x68581511;
        const H6: u32 = 0x64f98fa7;
        const H7: u32 = 0xbefa4fa4;

        pub const INIT_STATE: [Word; STATE_SIZE] = [H0, H1, H2, H3, H4, H5, H6, H7];

        pub const STATE_SIZE: usize = 8;
        pub const DIGEST_SIZE: usize = 7;

        pub use super::sha224_sha256_shared::*;
    }

    pub mod sha256 {
        const H0: u32 = 0x6a09e667;
        const H1: u32 = 0xbb67ae85;
        const H2: u32 = 0x3c6ef372;
        const H3: u32 = 0xa54ff53a;
        const H4: u32 = 0x510e527f;
        const H5: u32 = 0x9b05688c;
        const H6: u32 = 0x1f83d9ab;
        const H7: u32 = 0x5be0cd19;

        pub const INIT_STATE: [Word; STATE_SIZE] = [H0, H1, H2, H3, H4, H5, H6, H7];

        pub const STATE_SIZE: usize = 8;
        pub const DIGEST_SIZE: usize = 8;

        pub use super::sha224_sha256_shared::*;
    }

    pub mod sha384 {
        const H0: u64 = 0xcbbb9d5dc1059ed8;
        const H1: u64 = 0x629a292a367cd507;
        const H2: u64 = 0x9159015a3070dd17;
        const H3: u64 = 0x152fecd8f70e5939;
        const H4: u64 = 0x67332667ffc00b31;
        const H5: u64 = 0x8eb44a8768581511;
        const H6: u64 = 0xdb0c2e0d64f98fa7;
        const H7: u64 = 0x47b5481dbefa4fa4;

        pub const INIT_STATE: [Word; STATE_SIZE] = [H0, H1, H2, H3, H4, H5, H6, H7];

        pub const STATE_SIZE: usize = 8;
        pub const DIGEST_SIZE: usize = 6;

        pub use super::sha384_sha512_shared::*;
    }

    pub mod sha512 {
        const H0: u64 = 0x6a09e667f3bcc908;
        const H1: u64 = 0xbb67ae8584caa73b;
        const H2: u64 = 0x3c6ef372fe94f82b;
        const H3: u64 = 0xa54ff53a5f1d36f1;
        const H4: u64 = 0x510e527fade682d1;
        const H5: u64 = 0x9b05688c2b3e6c1f;
        const H6: u64 = 0x1f83d9abfb41bd6b;
        const H7: u64 = 0x5be0cd19137e2179;

        pub const INIT_STATE: [Word; STATE_SIZE] = [H0, H1, H2, H3, H4, H5, H6, H7];

        pub const STATE_SIZE: usize = 8;
        pub const DIGEST_SIZE: usize = 8;

        pub use super::sha384_sha512_shared::*;
    }
}

macro_rules! sha_impl {
    (algorithm = $algorithm:tt, hasher_name = $hasher_name:ident, digest_name = $digest_name:ident $(,)?) => {
        sha_impl! { @digest_impl $algorithm, $digest_name }
        sha_impl! { @hasher_struct_impl $algorithm, $hasher_name }
        sha_impl! { @hasher_trait_impl $algorithm, $hasher_name, $digest_name }
    };

    (@digest_impl $algo:ident, $name:ident) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $name(pub [context::$algo::Word; context::$algo::DIGEST_SIZE]);

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                // SAFETY:
                //   - u32s are always at least as aligned as u8
                unsafe {
                    ::std::slice::from_raw_parts(
                        &self.0 as *const _ as *const u8,
                        mem::size_of::<Self>(),
                    )
                }
            }
        }

        impl Encodable for $name {
            fn encode_hex(&self) -> String {
                self.as_ref().encode_hex()
            }

            fn encode_b64(&self) -> String {
                self.as_ref().encode_b64()
            }
        }
    };

    (@hasher_struct_impl $algo:ident, $name:ident) => {
        #[allow(unused)]
        #[derive(Debug, Clone)]
        pub struct $name {
            state: [context::$algo::Word; context::$algo::STATE_SIZE],
            message_length: context::$algo::MessageLength,
            unprocessed_data: Vec<u8>,
            finalized: bool,
        }

        impl $name {
            sha_impl! { @process_block $algo }
        }
    };

    (@hasher_trait_impl $algo:ident, $hasher_name:ident, $digest_name:ident) => {
        impl Hasher for $hasher_name {
            type Digest = $digest_name;

            const BLOCK_SIZE: usize = context::$algo::BLOCK_SIZE;

            fn new() -> Self {
                Self {
                    state: context::$algo::INIT_STATE,
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
                    self.process_block(block);
                }
                self.unprocessed_data.extend_from_slice(remaining);
            }

            fn finalize(&mut self) {
                use context::$algo::*;

                self.message_length +=
                    self.unprocessed_data.len() as MessageLength * u8::BITS as MessageLength;

                self.unprocessed_data.push(0x80);
                let k = self
                    .message_length
                    .wrapping_neg()
                    .wrapping_sub(BLOCK_SIZE as MessageLength)
                    .wrapping_sub(u8::BITS.into())
                    .rem_euclid(BLOCK_SIZE as MessageLength * u8::BITS as MessageLength);
                self.unprocessed_data
                    .extend_from_slice(&vec![0; k as usize / u8::BITS as usize]);
                self.unprocessed_data
                    .extend_from_slice(&self.message_length.to_be_bytes());

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
                use context::$algo::*;
                let mut digest_le = [0; DIGEST_SIZE];
                digest_le.copy_from_slice(&self.state[..DIGEST_SIZE]);
                $digest_name(digest_le.map(Word::to_be))
            }

            fn reset(&mut self) {
                self.state = context::$algo::INIT_STATE;
                self.message_length = 0;
                self.unprocessed_data = Vec::new();
                self.finalized = false;
            }

            fn set_message_len(&mut self, message_len: u64) {
                self.message_length = message_len.into();
            }
        }

        impl From<$digest_name> for $hasher_name {
            fn from(digest: $digest_name) -> Self {
                use context::$algo::*;
                let mut state_be = [0; STATE_SIZE];
                state_be[..DIGEST_SIZE].copy_from_slice(&digest.0[..]);

                Self {
                    state: state_be.map(Word::from_be),
                    message_length: 0,
                    unprocessed_data: Vec::new(),
                    finalized: false,
                }
            }
        }
    };

    (@process_block sha1) => {
        #[allow(non_snake_case)]
        fn process_block(&mut self, block: &[u8; context::sha1::BLOCK_SIZE]) {
            use context::sha1::*;

            // The message schedule
            let mut W: [Word; ROUNDS] = [0; ROUNDS];

            // Split the block into word sized chunks
            let chunks = cast_as_arrays(block);
            for (schedule_word, chunk) in W.iter_mut().zip(chunks.iter()) {
                *schedule_word = Word::from_be_bytes(*chunk);
            }

            // Expand the message into the rest of the schdule
            for t in 16..ROUNDS {
                W[t] = Word::rotate_left(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
            }

            // Working variables
            let [mut a, mut b, mut c, mut d, mut e] = self.state;
            let mut temp: u32;

            // Compute the core rounds
            for t in 0..ROUNDS {
                let f = match t {
                    0..=19 => Ch!(b, c, d),
                    20..=39 => Parity!(b, c, d),
                    40..=59 => Maj!(b, c, d),
                    60..=79 => Parity!(b, c, d),
                    // SAFETY: sha1 has 80 rounds so t is at most 79 meaning one of the match arms
                    // will always be hit
                    _ => unsafe { std::hint::unreachable_unchecked() },
                };
                let T = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(K[t / 20])
                    .wrapping_add(W[t]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = T;
            }

            // Compute the intermediate hash values
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);

            // Compute the new message length
            self.message_length += BLOCK_SIZE as MessageLength * u8::BITS as MessageLength;
        }
    };

    (@process_block $algo:ident) => {
        #[allow(non_snake_case)]
        fn process_block(&mut self, block: &[u8; context::$algo::BLOCK_SIZE]) {
            use context::$algo::*;

            // The message schedule
            let mut W: [Word; ROUNDS] = [0; ROUNDS];

            // Split the block into word sized chunks
            let chunks = cast_as_arrays(block);
            for (schedule_word, chunk) in W.iter_mut().zip(chunks.iter()) {
                *schedule_word = Word::from_be_bytes(*chunk);
            }

            // Expand the message into the rest of the schdule
            for t in 16..ROUNDS {
                W[t] = σ_1(W[t - 2])
                    .wrapping_add(W[t - 7])
                    .wrapping_add(σ_0(W[t - 15]))
                    .wrapping_add(W[t - 16]);
            }

            // Working variables
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            let mut temp: u32;

            // Compute the core rounds
            for t in 0..ROUNDS {
                let T1 = h
                    .wrapping_add(Σ_1(e))
                    .wrapping_add(Ch!(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(W[t]);
                let T2 = Σ_0(a).wrapping_add(Maj!(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(T1);
                d = c;
                c = b;
                b = a;
                a = T1.wrapping_add(T2);
            }

            // Compute the intermediate hash values
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);

            // Compute the new message length
            self.message_length += context::$algo::BLOCK_SIZE as context::$algo::MessageLength
                * u8::BITS as context::$algo::MessageLength;
        }
    };
}

sha_impl! {
    algorithm   = sha1,
    hasher_name = Sha1,
    digest_name = Sha1Digest,
}

sha_impl! {
    algorithm   = sha224,
    hasher_name = Sha224,
    digest_name = Sha224Digest,
}

sha_impl! {
    algorithm   = sha256,
    hasher_name = Sha256,
    digest_name = Sha256Digest,
}

sha_impl! {
    algorithm   = sha384,
    hasher_name = Sha384,
    digest_name = Sha384Digest,
}

sha_impl! {
    algorithm   = sha512,
    hasher_name = Sha512,
    digest_name = Sha512Digest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Encodable;

    // test vectors from https://www.di-mgt.com.au/sha_testvectors.html
    #[test]
    fn test_sha1_testvectors() {
        let test_vectors = [
            ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "a49b2446a02c645bf419f995b67091253a04a259"
            ),
            (
                &"a".repeat(1_000_000),
                "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
            ),
            #[cfg(feature = "long_tests")]
            (
                &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
                "7789f0c9ef7bfc40d93311143dfbe69e2017f592"
            ),
        ];
        let mut hasher = Sha1::new();
        for (test, correct) in test_vectors {
            hasher.update(test);
            hasher.finalize();
            let hash = hasher.digest();
            assert_eq!(hash.encode_hex(), correct);
            hasher.reset();
        }
    }

    #[test]
    fn test_sha1_to_from_digest() {
        let mut hasher = Sha1::new();
        hasher.update("Wow this string sure isn't very long.");
        hasher.finalize();
        let recovered: Sha1 = hasher.digest().into();
        assert_eq!(hasher.state, recovered.state)
    }

    // test vectors from https://www.di-mgt.com.au/sha_testvectors.html
    #[test]
    fn test_sha224_testvectors() {
        let test_vectors = [
            ("abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"),
            ("", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"
            ),
            (
                &"a".repeat(1_000_000),
                "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
            ),
            #[cfg(feature = "long_tests")]
            (
                &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
                "b5989713ca4fe47a009f8621980b34e6d63ed3063b2a0a2c867d8a85"
            ),
        ];
        let mut hasher = Sha224::new();
        for (test, correct) in test_vectors {
            hasher.update(test);
            hasher.finalize();
            let hash = hasher.digest();
            assert_eq!(hash.encode_hex(), correct);
            hasher.reset();
        }
    }

    #[test]
    #[should_panic(expected = "State not recoverable")]
    fn test_sha224_to_from_digest() {
        let mut hasher = Sha224::new();
        hasher.update("Wow this string sure isn't very long.");
        hasher.finalize();
        let recovered: Sha224 = hasher.digest().into();
        assert_eq!(hasher.state, recovered.state, "State not recoverable")
    }

    // test vectors from https://www.di-mgt.com.au/sha_testvectors.html
    #[test]
    fn test_sha256_testvectors() {
        let test_vectors = [
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
            ),
            (
                &"a".repeat(1_000_000),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
            ),
            #[cfg(feature = "long_tests")]
            (
                &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
                "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"
            ),
        ];
        let mut hasher = Sha256::new();
        for (test, correct) in test_vectors {
            hasher.update(test);
            hasher.finalize();
            let hash = hasher.digest();
            assert_eq!(hash.encode_hex(), correct);
            hasher.reset();
        }
    }

    #[test]
    fn test_sha256_to_from_digest() {
        let mut hasher = Sha256::new();
        hasher.update("Wow this string sure isn't very long.");
        hasher.finalize();
        let recovered: Sha256 = hasher.digest().into();
        assert_eq!(hasher.state, recovered.state)
    }

    // test vectors from https://www.di-mgt.com.au/sha_testvectors.html
    #[test]
    fn test_sha384_testvectors() {
        let test_vectors = [
            ("abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            ("", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
            ),
            (
                &"a".repeat(1_000_000),
                "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
            ),
            #[cfg(feature = "long_tests")]
            (
                &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
                "5441235cc0235341ed806a64fb354742b5e5c02a3c5cb71b5f63fb793458d8fdae599c8cd8884943c04f11b31b89f023"
            ),
        ];
        let mut hasher = Sha384::new();
        for (test, correct) in test_vectors {
            hasher.update(test);
            hasher.finalize();
            let hash = hasher.digest();
            assert_eq!(hash.encode_hex(), correct);
            hasher.reset();
        }
    }

    #[test]
    #[should_panic(expected = "State not recoverable")]
    fn test_sha384_to_from_digest() {
        let mut hasher = Sha384::new();
        hasher.update("Wow this string sure isn't very long.");
        hasher.finalize();
        let recovered: Sha384 = hasher.digest().into();
        assert_eq!(hasher.state, recovered.state, "State not recoverable")
    }

    // test vectors from https://www.di-mgt.com.au/sha_testvectors.html
    #[test]
    fn test_sha512_testvectors() {
        let test_vectors = [
            ("abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
            ("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            ),
            (
                &"a".repeat(1_000_000),
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            ),
            #[cfg(feature = "long_tests")]
            (
                &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
                "b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086"
            ),
        ];
        let mut hasher = Sha512::new();
        for (test, correct) in test_vectors {
            hasher.update(test);
            hasher.finalize();
            let hash = hasher.digest();
            assert_eq!(hash.encode_hex(), correct);
            hasher.reset();
        }
    }

    #[test]
    fn test_sha512_to_from_digest() {
        let mut hasher = Sha512::new();
        hasher.update("Wow this string sure isn't very long.");
        hasher.finalize();
        let recovered: Sha512 = hasher.digest().into();
        assert_eq!(hasher.state, recovered.state)
    }
}
