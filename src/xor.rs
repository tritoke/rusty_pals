use color_eyre::eyre::{ensure, Result};

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
/// let mut out = Vec::from(b"def");
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
}
