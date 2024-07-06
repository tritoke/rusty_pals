use std::mem;

use crate::crypto::Hasher;
use crate::encoding::Encodable;

pub mod constants {
    #[rustfmt::skip]
    pub const K_32: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    #[rustfmt::skip]
    pub const K_64: [u64; 80] = [
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
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ];

    pub mod sha224_constants {
        pub const H0: u32 = 0xc1059ed8;
        pub const H1: u32 = 0x367cd507;
        pub const H2: u32 = 0x3070dd17;
        pub const H3: u32 = 0xf70e5939;
        pub const H4: u32 = 0xffc00b31;
        pub const H5: u32 = 0x68581511;
        pub const H6: u32 = 0x64f98fa7;
        pub const H7: u32 = 0xbefa4fa4;
    }

    pub mod sha256_constants {
        pub const H0: u32 = 0x6a09e667;
        pub const H1: u32 = 0xbb67ae85;
        pub const H2: u32 = 0x3c6ef372;
        pub const H3: u32 = 0xa54ff53a;
        pub const H4: u32 = 0x510e527f;
        pub const H5: u32 = 0x9b05688c;
        pub const H6: u32 = 0x1f83d9ab;
        pub const H7: u32 = 0x5be0cd19;
    }

    pub mod sha384_constants {
        pub const H0: u64 = 0xcbbb9d5dc1059ed8;
        pub const H1: u64 = 0x629a292a367cd507;
        pub const H2: u64 = 0x9159015a3070dd17;
        pub const H3: u64 = 0x152fecd8f70e5939;
        pub const H4: u64 = 0x67332667ffc00b31;
        pub const H5: u64 = 0x8eb44a8768581511;
        pub const H6: u64 = 0xdb0c2e0d64f98fa7;
        pub const H7: u64 = 0x47b5481dbefa4fa4;
    }

    pub mod sha512_constants {
        pub const H0: u64 = 0x6a09e667f3bcc908;
        pub const H1: u64 = 0xbb67ae8584caa73b;
        pub const H2: u64 = 0x3c6ef372fe94f82b;
        pub const H3: u64 = 0xa54ff53a5f1d36f1;
        pub const H4: u64 = 0x510e527fade682d1;
        pub const H5: u64 = 0x9b05688c2b3e6c1f;
        pub const H6: u64 = 0x1f83d9abfb41bd6b;
        pub const H7: u64 = 0x5be0cd19137e2179;
    }
}

macro_rules! impl_sha2digest {
    ($name:ident, size = $size:literal, alignment = $alignment:literal, from = $from_ty:ty) => {
        #[repr(align($alignment))]
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $name(pub [u8; $size]);

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Encodable for $name {
            fn encode_hex(&self) -> String {
                self.0.encode_hex()
            }

            fn encode_b64(&self) -> String {
                self.0.encode_b64()
            }
        }

        impl From<[$from_ty; $size / $alignment]> for $name {
            fn from(state: [$from_ty; $size / $alignment]) -> Self {
                // Safety: u32 can always be safely cast into u8's
                Self(unsafe {
                    mem::transmute::<[$from_ty; $size / $alignment], [u8; $size]>(
                        state.map(<$from_ty>::to_be),
                    )
                })
            }
        }

        impl From<$name> for [$from_ty; $size / $alignment] {
            fn from($name(inner_bytes): $name) -> Self {
                // Safety: the struct guarantees 4 byte alignment, thus it is always safe to transmute
                // back from [u8] to [u32]
                unsafe {
                    mem::transmute::<[u8; $size], [$from_ty; $size / $alignment]>(inner_bytes)
                }
                .map(<$from_ty>::to_be)
            }
        }
    };
}
impl_sha2digest!(Sha224Digest, size = 28, alignment = 4, from = u32);
impl_sha2digest!(Sha256Digest, size = 32, alignment = 4, from = u32);
impl_sha2digest!(Sha384Digest, size = 48, alignment = 8, from = u64);
impl_sha2digest!(Sha512Digest, size = 64, alignment = 8, from = u64);

#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    message_length: u64,
    unprocessed_data: Vec<u8>,
    finalized: bool,
}

// impl Hasher for Sha256 {
//     type Digest = Sha256Digest;

//     const BLOCK_SIZE: usize = 64;

//     fn new() -> Self {
//         Self {
//             state: [H0, H1, H2, H3, H4],
//             message_length: 0,
//             unprocessed_data: Vec::new(),
//             finalized: false,
//         }
//     }

//     fn update(&mut self, data: impl AsRef<[u8]>) {
//         assert!(!self.finalized, "Cannot update a finalized Hasher.");

//         self.unprocessed_data.extend_from_slice(data.as_ref());
//         let data = mem::take(&mut self.unprocessed_data);
//         let (blocks, remaining) = as_chunks(&data);
//         for block in blocks {
//             unsafe { self.process_block(block) };
//         }
//         self.unprocessed_data.extend_from_slice(remaining);
//     }

//     fn finalize(&mut self) {
//         self.message_length += self.unprocessed_data.len() as u64 * 8;

//         self.unprocessed_data.push(0x80);
//         let k = (-(self.message_length as i64) - 64 - 8).rem_euclid(512);
//         self.unprocessed_data
//             .extend_from_slice(&vec![0; k as usize / 8]);
//         self.unprocessed_data
//             .extend_from_slice(&self.message_length.to_be_bytes());

//         self.update("");
//         self.finalized = true;

//         assert!(
//             self.unprocessed_data.is_empty(),
//             "There must be no unprocessed data after finalization."
//         );
//     }

//     fn digest(&self) -> Self::Digest {
//         assert!(
//             self.finalized,
//             "Attempting to get the digest of an unfinalized Hasher."
//         );
//         self.state.into()
//     }

//     fn reset(&mut self) {
//         self.state = [H0, H1, H2, H3, H4];
//         self.message_length = 0;
//         self.unprocessed_data = Vec::new();
//         self.finalized = false;
//     }

//     fn set_message_len(&mut self, message_len: u64) {
//         self.message_length = message_len;
//     }
// }

// impl From<<Sha1 as Hasher>::Digest> for Sha1 {
//     fn from(digest: <Sha1 as Hasher>::Digest) -> Self {
//         Self {
//             state: digest.into(),
//             message_length: 0,
//             unprocessed_data: Vec::new(),
//             finalized: false,
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::encoding::Encodable;

//     // test vectors from https://www.di-mgt.com.au/sha_testvectors.html
//     #[test]
//     fn test_sha1_nist_vectors() {
//         let test_vectors = [
//             ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
//             ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
//             (
//                 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
//                 "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
//             ),
//             (
//                 "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
//                 "a49b2446a02c645bf419f995b67091253a04a259"
//             ),
//             (
//                 &"a".repeat(1_000_000),
//                 "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
//             ),
//             // This test passes but takes several seconds to run
//             // (
//             //     &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
//             //     "7789f0c9ef7bfc40d93311143dfbe69e2017f592"
//             // ),
//         ];
//         let mut hasher = Sha1::new();
//         for (test, correct) in test_vectors {
//             hasher.update(test);
//             hasher.finalize();
//             let hash = hasher.digest();
//             assert_eq!(hash.encode_hex(), correct);
//             hasher.reset();
//         }
//     }

//     #[test]
//     fn test_sha1_to_from_digest() {
//         let mut hasher = Sha1::new();
//         hasher.update("Wow this string sure isn't very long.");
//         hasher.finalize();
//         let recovered: Sha1 = hasher.digest().into();
//         assert_eq!(hasher.state, recovered.state)
//     }

//     #[test]
//     fn test_sha1_digest_is_be() {
//         let digest: Digest = [1, 2, 3, 4, 5].into();
//         let repr = [1, 2, 3, 4, 5].map(u32::to_be_bytes).concat();
//         assert_eq!(&digest.0[..], &repr[..]);
//     }

//     #[test]
//     fn test_sha1_digest_to_state() {
//         let digest0: Digest = [5, 4, 3, 2, 1].into();
//         let digest1: [u32; 5] = digest0.into();
//         let digest2: Digest = digest1.into();
//         assert_eq!(digest0, digest2);
//     }
// }
