use std::arch::x86_64::*;
use std::mem;

use super::{Aes128Key, Aes192Key, Aes256Key, AesKey, Block};

/// Helpers derived from <https://www.intel.com/content/dam/develop/external/us/en/documents/aes-wp-2012-09-22-v01-165683.pdf>
#[allow(clippy::needless_late_init)]
mod helpers {
    use std::arch::x86_64::*;
    use std::{array, mem, ptr};

    // Requires aes and sse2
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

    // Requires aes and sse2
    pub unsafe fn aes_128_key_expansion(key: [u8; 16]) -> [__m128i; 11] {
        let mut t1: __m128i;
        let mut t2: __m128i;
        let mut key_schedule = array::from_fn(|_| _mm_setzero_si128());

        t1 = _mm_loadu_si128(key.as_ptr().cast());
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

    // Requires aes and sse2
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

    // Requires aes and sse2
    #[rustfmt::skip]
    pub unsafe fn aes_192_key_expansion(key: [u8; 24]) -> [__m128i; 13] {
        #[inline]
        unsafe fn shuffle<const MASK: i32>(a: __m128i, b: __m128i) -> __m128i {
            mem::transmute(_mm_shuffle_pd::<MASK>(mem::transmute(a), mem::transmute(b)))
        }

        let mut t2: __m128i;
        let mut key_schedule = array::from_fn(|_| _mm_setzero_si128());

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

    // Requires aes and sse2
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

    // Requires aes and sse2
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

    // Requires aes and sse2
    pub unsafe fn aes_256_key_expansion(key: [u8; 32]) -> [__m128i; 15] {
        let mut t1: __m128i;
        let mut t2: __m128i;
        let mut t3: __m128i;
        let mut key_schedule = array::from_fn(|_| _mm_setzero_si128());

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

/// Safety precondition: AES and SSE2 instructions must be present
#[inline(always)]
pub(super) unsafe fn aes128_expand_key(key: &[u8; 16]) -> Aes128Key {
    Aes128Key {
        key_schedule: mem::transmute::<[__m128i; 11], [[u32; 4]; 11]>(
            helpers::aes_128_key_expansion(*key),
        ),
    }
}

/// Safety precondition: AES and SSE2 instructions must be present
#[inline(always)]
pub(super) unsafe fn aes192_expand_key(key: &[u8; 24]) -> Aes192Key {
    Aes192Key {
        key_schedule: mem::transmute::<[__m128i; 13], [[u32; 4]; 13]>(
            helpers::aes_192_key_expansion(*key),
        ),
    }
}

/// Safety precondition: AES and SSE2 instructions must be present
#[inline(always)]
pub(super) unsafe fn aes256_expand_key(key: &[u8; 32]) -> Aes256Key {
    Aes256Key {
        key_schedule: mem::transmute::<[__m128i; 15], [[u32; 4]; 15]>(
            helpers::aes_256_key_expansion(*key),
        ),
    }
}

/// Safety precondition: AES and SSE2 instructions must be present
#[inline(always)]
pub(super) unsafe fn encrypt_block<const R: usize>(
    key: &AesKey<R>,
    block: &Block,
    out_block: &mut Block,
) {
    // SAFETY: loadu has no alignment requirements
    let mut t = _mm_loadu_si128(block.as_ptr().cast());

    t = _mm_xor_si128(t, key.rk_simd(0));
    for round in 1..R - 1 {
        t = _mm_aesenc_si128(t, key.rk_simd(round));
    }
    t = _mm_aesenclast_si128(t, key.rk_simd(R - 1));

    // SAFETY: storeu has no alignment requirements
    _mm_storeu_si128(out_block.as_mut_ptr().cast(), t);
}

/// Safety precondition: AES and SSE2 instructions must be present
#[inline(always)]
pub(super) unsafe fn decrypt_block<const R: usize>(
    key: &AesKey<R>,
    block: &Block,
    out_block: &mut Block,
) {
    // SAFETY: loadu has no alignment requirements and transmute checks the size
    let mut t = _mm_loadu_si128(block.as_ptr().cast());

    t = _mm_xor_si128(t, key.rk_simd(R - 1));
    for round in (1..R - 1).rev() {
        t = _mm_aesdec_si128(t, _mm_aesimc_si128(key.rk_simd(round)));
    }
    t = _mm_aesdeclast_si128(t, key.rk_simd(0));

    // SAFETY: storeu has no alignment requirements
    _mm_storeu_si128(out_block.as_mut_ptr().cast(), t);
}
