use crate::crypto::Hasher;
use std::arch::x86_64::*;
use std::mem;

pub mod constants {
    pub const H0: u32 = 0x67452301;
    pub const H1: u32 = 0xEFCDAB89;
    pub const H2: u32 = 0x98BADCFE;
    pub const H3: u32 = 0x10325476;
    pub const H4: u32 = 0xC3D2e1F0;
    pub const MASK0: u64 = 0x0001020304050607;
    pub const MASK1: u64 = 0x08090a0b0c0d0e0f;
}
use crate::util::{as_chunks, cast_as_array};
use constants::*;

#[derive(Debug, Clone)]
struct Sha1 {
    state: [u32; 5],
    message_length: u64,
    unprocessed_data: Vec<u8>,
    finalized: bool,
}

impl Sha1 {
    /// Adapted from: https://stackoverflow.com/questions/21107350/how-can-i-access-sha-intrinsic
    unsafe fn process_block(&mut self, block: &[u8; 64]) {
        let mut abcd: __m128i;
        let mut e0: __m128i;
        let abcd_save: __m128i;
        let e0_save: __m128i;
        let mut e1: __m128i;
        let mask: __m128i;
        let mut msg0: __m128i;
        let mut msg1: __m128i;
        let mut msg2: __m128i;
        let mut msg3: __m128i;

        // Load initial values
        abcd = _mm_loadu_si128(self.state.as_ptr().cast());
        e0 = _mm_set_epi32(self.state[4] as i32, 0, 0, 0);
        abcd = _mm_shuffle_epi32::<0x1B>(abcd);
        mask = _mm_set_epi64x(MASK0 as i64, MASK1 as i64);

        // Save current hash
        abcd_save = abcd;
        e0_save = e0;

        // Rounds 0-3
        msg0 = _mm_loadu_si128(block.as_ptr().cast::<__m128i>().offset(0));
        msg0 = _mm_shuffle_epi8(msg0, mask);
        e0 = _mm_add_epi32(e0, msg0);
        e1 = abcd;
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);

        // Rounds 4-7
        msg1 = _mm_loadu_si128(block.as_ptr().cast::<__m128i>().offset(1));
        msg1 = _mm_shuffle_epi8(msg1, mask);
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = abcd;
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);

        // Rounds 8-11
        msg2 = _mm_loadu_si128(block.as_ptr().cast::<__m128i>().offset(2));
        msg2 = _mm_shuffle_epi8(msg2, mask);
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = abcd;
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 12-15
        msg3 = _mm_loadu_si128(block.as_ptr().cast::<__m128i>().offset(3));
        msg3 = _mm_shuffle_epi8(msg3, mask);
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = abcd;
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e1);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 16-19
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = abcd;
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32::<0>(abcd, e0);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 20-23
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = abcd;
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 24-27
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = abcd;
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 28-31
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = abcd;
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 32-35
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = abcd;
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e0);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 36-39
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = abcd;
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32::<1>(abcd, e1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 40-43
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = abcd;
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 44-47
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = abcd;
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 48-51
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = abcd;
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 52-55
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = abcd;
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e1);
        msg0 = _mm_sha1msg1_epu32(msg0, msg1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 56-59
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = abcd;
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32::<2>(abcd, e0);
        msg1 = _mm_sha1msg1_epu32(msg1, msg2);
        msg0 = _mm_xor_si128(msg0, msg2);

        // Rounds 60-63
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = abcd;
        msg0 = _mm_sha1msg2_epu32(msg0, msg3);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
        msg2 = _mm_sha1msg1_epu32(msg2, msg3);
        msg1 = _mm_xor_si128(msg1, msg3);

        // Rounds 64-67
        e0 = _mm_sha1nexte_epu32(e0, msg0);
        e1 = abcd;
        msg1 = _mm_sha1msg2_epu32(msg1, msg0);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);
        msg3 = _mm_sha1msg1_epu32(msg3, msg0);
        msg2 = _mm_xor_si128(msg2, msg0);

        // Rounds 68-71
        e1 = _mm_sha1nexte_epu32(e1, msg1);
        e0 = abcd;
        msg2 = _mm_sha1msg2_epu32(msg2, msg1);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);
        msg3 = _mm_xor_si128(msg3, msg1);

        // Rounds 72-75
        e0 = _mm_sha1nexte_epu32(e0, msg2);
        e1 = abcd;
        msg3 = _mm_sha1msg2_epu32(msg3, msg2);
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e0);

        // Rounds 76-79
        e1 = _mm_sha1nexte_epu32(e1, msg3);
        e0 = abcd;
        abcd = _mm_sha1rnds4_epu32::<3>(abcd, e1);

        // Add values back to state
        e0 = _mm_sha1nexte_epu32(e0, e0_save);
        abcd = _mm_add_epi32(abcd, abcd_save);

        // Save state
        abcd = _mm_shuffle_epi32::<0x1B>(abcd);
        _mm_storeu_si128(self.state.as_mut_ptr().cast(), abcd);
        self.state[4] = _mm_extract_epi32::<3>(e0) as u32;
        self.message_length += 512;
    }
}

impl Hasher for Sha1 {
    type Digest = [u8; 20];

    fn new() -> Self {
        Self {
            state: [H0, H1, H2, H3, H4],
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
            .extend_from_slice(&self.message_length.to_be_bytes());

        self.update("");
        self.finalized = true;

        assert!(
            dbg!(self).unprocessed_data.is_empty(),
            "There must be no unprocessed data after finalization."
        );
    }

    fn digest(&self) -> Self::Digest {
        assert!(
            self.finalized,
            "Attempting to get the digest of an unfinalized Hasher."
        );
        self.state
            .map(u32::to_be_bytes)
            .concat()
            .try_into()
            .unwrap()
    }

    fn reset(&mut self) {
        self.state = [H0, H1, H2, H3, H4];
        self.message_length = 0;
        self.unprocessed_data = Vec::new();
        self.finalized = false;
    }
}

mod tests {
    use super::*;
    use crate::encoding::Encodable;

    #[test]
    // test vectors from https://www.di-mgt.com.au/sha_testvectors.html
    fn test_sha1_nist_vectors() {
        let test_vectors = [
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
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
            // This test passes but takes several seconds to run
            // (
            //     &"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno".repeat(16_777_216),
            //     "7789f0c9ef7bfc40d93311143dfbe69e2017f592"
            // ),
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
}
