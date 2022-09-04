use crate::fit::{edit_distance, score_text};
use color_eyre::eyre::{ensure, eyre, Result};
use std::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
use std::ops::RangeInclusive;

/// XOR two blocks of data together
/// ```
/// use rusty_pals::xor::xor_blocks;
/// assert_eq!(xor_blocks("abc", "def").unwrap(), [5, 7, 5]);
/// ```
pub fn xor_blocks(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let a = a.as_ref();
    let b = b.as_ref();

    // ensure we have the same length blocks
    ensure!(
        a.len() == b.len(),
        "Mismatch in block length: {} != {}",
        a.len(),
        b.len()
    );

    let xorred = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();

    Ok(xorred)
}

/// XOR two blocks of data, writing the result into an output slice
/// ```
/// use rusty_pals::xor::xor_blocks_into;
/// let mut out = vec![0; 3];
/// assert!(xor_blocks_into("abc", "def", out.as_mut_slice()).is_ok());
/// assert_eq!(out, [5, 7, 5]);
/// ```
pub fn xor_blocks_into(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>, out: &mut [u8]) -> Result<()> {
    let a = a.as_ref();
    let b = b.as_ref();

    // ensure we have the same length blocks
    ensure!(
        a.len() == b.len(),
        "Mismatch in block length: {} != {}",
        a.len(),
        b.len()
    );

    // ensure the output has enough space
    ensure!(a.len() <= out.len(), "Insuffient space in output slice.",);

    let xorred = a.iter().zip(b.iter()).map(|(x, y)| x ^ y);
    for (x, y) in out.iter_mut().zip(xorred) {
        *x = y;
    }

    Ok(())
}

/// XOR two blocks of data, writing the result into the second block
/// ```
/// use rusty_pals::xor::xor_blocks_together;
/// let mut out = b"def".to_vec();
/// assert!(xor_blocks_together("abc", out.as_mut_slice()).is_ok());
/// assert_eq!(out, [5, 7, 5]);
/// ```
pub fn xor_blocks_together(a: impl AsRef<[u8]>, b: &mut [u8]) -> Result<()> {
    let a = a.as_ref();

    // ensure we have the same length blocks
    ensure!(
        a.len() == b.len(),
        "Mismatch in block length: {} != {}",
        a.len(),
        b.len()
    );

    for (x, y) in a.iter().zip(b.iter_mut()) {
        *y ^= *x;
    }

    Ok(())
}

/// XOR a block of data with a key
/// ```
/// use rusty_pals::xor::xor_with_key;
/// assert_eq!(xor_with_key("abc", "a").unwrap(), [0, 3, 2]);
/// ```
pub fn xor_with_key(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    let data = data.as_ref();
    let key = key.as_ref();

    ensure!(!key.is_empty(), "XOR Key cannot be empty.");

    let xorred = data
        .iter()
        .zip(key.iter().cycle())
        .map(|(x, y)| x ^ y)
        .collect();

    Ok(xorred)
}

/// XOR a block of data with a key, into an output slice
/// ```
/// use rusty_pals::xor::xor_with_key_into;
/// let data = "abcdef";
/// let key = "db";
/// let mut out = vec![0; data.len()];
/// assert!(xor_with_key_into(data, key, out.as_mut_slice()).is_ok());
/// assert_eq!(out, [5, 0, 7, 6, 1, 4]);
/// ```
pub fn xor_with_key_into(
    data: impl AsRef<[u8]>,
    key: impl AsRef<[u8]>,
    out: &mut [u8],
) -> Result<()> {
    let data = data.as_ref();
    let key = key.as_ref();

    ensure!(!key.is_empty(), "XOR Key cannot be empty.");
    ensure!(out.len() >= data.len(), "Insuffient space in output slice.");

    let xorred = data.iter().zip(key.iter().cycle()).map(|(x, y)| x ^ y);

    for (x, y) in out.iter_mut().zip(xorred) {
        *x = y;
    }

    Ok(())
}

/// Use SIMD to accelerate XORing a 16 byte block
/// ```
/// use rusty_pals::xor::xor_block_simd;
/// let block_1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// let block_2 = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
/// let xorred = unsafe { xor_block_simd(&block_1, &block_2) };
/// assert_eq!(xorred, [15; 16])
/// ```
pub fn xor_block_simd(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    // SAFETY: unaligned load MUST be used here
    unsafe {
        let b1 = _mm_loadu_si128(a.as_ptr() as *const _);
        let b2 = _mm_loadu_si128(b.as_ptr() as *const _);
        let xorred = _mm_xor_si128(b1, b2);
        let mut out: [u8; 16] = [0; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut _, xorred);
        out
    }
}

/// Use SIMD to accelerate XORing a 16 byte block, into another
/// ```
/// use rusty_pals::xor::xor_block_simd_into;
/// let block_1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// let mut block_2 = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
/// unsafe { xor_block_simd_into(&block_1, &mut block_2) };
/// assert_eq!(block_2, [15; 16])
/// ```
pub fn xor_block_simd_into(a: &[u8; 16], b: &mut [u8; 16]) {
    unsafe {
        // SAFETY: unaligned load MUST be used here
        let b1 = _mm_loadu_si128(a.as_ptr() as *const _);
        let b2 = _mm_loadu_si128(b.as_ptr() as *const _);
        let xorred = _mm_xor_si128(b1, b2);
        _mm_storeu_si128(b.as_mut_ptr() as *mut _, xorred);
    }
}

/// Break a xor with a single byte key, returns the byte key
pub fn break_single_xor(data: &[u8]) -> Result<u8> {
    let mut xorred = data.to_vec();
    let mut max_key = 0;
    let mut max_score = u64::MIN;

    for key in 0..=u8::MAX {
        xor_with_key_into(&data, [key], &mut xorred)?;
        let score = score_text(&xorred);
        if score > max_score {
            max_score = score;
            max_key = key;
        }
    }

    Ok(max_key)
}

/// Break a repeating key XOR, returns the key
pub fn break_repeating_key_xor<const AVERAGE_BLOCKS: usize>(
    data: impl AsRef<[u8]>,
    key_range: RangeInclusive<usize>,
) -> Result<Vec<u8>> {
    let data = data.as_ref();
    let mut min_norm = f64::INFINITY;
    let mut best_key_size = 0;
    for key_size in key_range {
        let block1 = data
            .get(..key_size * AVERAGE_BLOCKS)
            .ok_or_else(|| eyre!("input data too small"))?;
        let block2 = data
            .get(key_size * AVERAGE_BLOCKS..key_size * AVERAGE_BLOCKS * 2)
            .ok_or_else(|| eyre!("input data too small"))?;
        let norm = edit_distance(block1, block2) as f64 / key_size as f64;
        if norm < min_norm {
            min_norm = norm;
            best_key_size = key_size;
        }
    }

    let mut key = Vec::new();
    for offset in 0..best_key_size {
        let text: Vec<_> = data
            .iter()
            .skip(offset)
            .step_by(best_key_size)
            .copied()
            .collect();
        key.push(break_single_xor(&text)?);
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_blocks() {
        let a = [1, 2, 3, 4];
        let b = [101, 102, 103, 104];
        assert_eq!(xor_blocks(a, b).unwrap(), [100, 100, 100, 108]);
    }

    #[test]
    fn test_xor_blocks_fails_len_mismatch() {
        let a = [1, 2, 3, 4];
        let b = [101, 102, 103];
        assert!(xor_blocks(a, b).is_err());
    }

    #[test]
    fn test_xor_blocks_into() {
        let a = [1, 2, 3, 4];
        let b = [101, 102, 103, 104];
        let mut out = vec![0, 0, 0, 0];
        assert!(xor_blocks_into(a, b, out.as_mut_slice()).is_ok());
        assert_eq!(out, [100, 100, 100, 108]);
    }

    #[test]
    fn test_xor_blocks_into_fails_len_mismatch() {
        let a = [1, 2, 3, 4];
        let b = [101, 102, 103];
        let mut out = vec![0, 0, 0, 0];
        assert!(xor_blocks_into(a, b, out.as_mut_slice()).is_err());
    }

    #[test]
    fn test_xor_blocks_output_len_too_small_fails() {
        let a = [1, 2, 3, 4];
        let b = [101, 102, 103];
        let mut out = vec![];
        assert!(xor_blocks_into(a, b, out.as_mut_slice()).is_err());
    }

    #[test]
    fn test_xor_blocks_together() {
        let a = [1, 2, 3, 4];
        let mut b = vec![101, 102, 103, 104];
        assert!(xor_blocks_together(a, b.as_mut_slice()).is_ok());
        assert_eq!(b, [100, 100, 100, 108]);
    }

    #[test]
    fn test_xor_blocks_together_fails_len_mismatch() {
        let a = [1, 2, 3, 4];
        let mut b = vec![101, 102, 103];
        assert!(xor_blocks_together(a, b.as_mut_slice()).is_err());
    }

    #[test]
    fn test_xor_with_key_length_1() {
        let data = [1, 2, 3, 4];
        assert_eq!(xor_with_key(data, "E").unwrap(), [68, 71, 70, 65]);
    }

    #[test]
    fn test_xor_with_key_length_2() {
        let data = [1, 2, 3, 4, 5];
        assert_eq!(xor_with_key(data, "PE").unwrap(), [81, 71, 83, 65, 85]);
    }

    #[test]
    fn test_xor_with_key_empty_key_fails() {
        let data = [1, 2, 3, 4, 5];
        assert!(xor_with_key(data, "").is_err());
    }

    #[test]
    fn test_xor_with_key_into_length_1() {
        let data = [1, 2, 3, 4];
        let mut out = vec![0; 4];
        assert!(xor_with_key_into(data, "E", out.as_mut_slice()).is_ok());
        assert_eq!(out, [68, 71, 70, 65]);
    }

    #[test]
    fn test_xor_with_key_into_length_2() {
        let data = [1, 2, 3, 4, 5];
        let mut out = vec![0; 5];
        assert!(xor_with_key_into(data, "PE", out.as_mut_slice()).is_ok());
        assert_eq!(out, [81, 71, 83, 65, 85]);
    }

    #[test]
    fn test_xor_with_key_into_empty_key_fails() {
        let data = [1, 2, 3, 4, 5];
        let mut out = vec![0; 5];
        assert!(xor_with_key_into(data, "", out.as_mut_slice()).is_err());
    }

    #[test]
    fn test_xor_with_key_into_output_len_too_small_fails() {
        let data = [1, 2, 3, 4, 5];
        let mut out = vec![0; 4];
        assert!(xor_with_key_into(data, "B", out.as_mut_slice()).is_err());
    }

    #[test]
    #[cfg(target_feature = "sse2")]
    fn test_xor_block_simd() {
        let b1 = [
            243, 158, 45, 150, 205, 223, 233, 225, 185, 7, 222, 69, 206, 190, 183, 78,
        ];
        let b2 = [
            26, 13, 61, 74, 96, 85, 87, 197, 214, 22, 169, 251, 114, 4, 204, 80,
        ];
        let correct = [
            233, 147, 16, 220, 173, 138, 190, 36, 111, 17, 119, 190, 188, 186, 123, 30,
        ];
        let xorred = xor_block_simd(&b1, &b2);
        assert_eq!(xorred, correct);
    }

    #[test]
    #[cfg(target_feature = "sse2")]
    fn test_xor_block_simd_into() {
        let b1 = [
            243, 158, 45, 150, 205, 223, 233, 225, 185, 7, 222, 69, 206, 190, 183, 78,
        ];
        let mut b2 = [
            26, 13, 61, 74, 96, 85, 87, 197, 214, 22, 169, 251, 114, 4, 204, 80,
        ];
        let correct = [
            233, 147, 16, 220, 173, 138, 190, 36, 111, 17, 119, 190, 188, 186, 123, 30,
        ];
        xor_block_simd_into(&b1, &mut b2);
        assert_eq!(b2, correct);
    }
}
