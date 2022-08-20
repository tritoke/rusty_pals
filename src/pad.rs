use color_eyre::eyre::{ensure, eyre, Result};

/// Implement the PKCS#7 padding scheme
pub fn pkcs7(data: impl AsRef<[u8]>, block_length: u8) -> Vec<u8> {
    let data = data.as_ref();
    let mut out = data.to_vec();
    pkcs7_into(&mut out, block_length);
    out
}

/// Implement the PKCS#7 padding scheme, writing onto the end of a Vec
pub fn pkcs7_into(data: &mut Vec<u8>, block_length: u8) {
    let pad = block_length - (data.len() % (block_length as usize)) as u8;
    let padding = vec![pad; pad as usize];
    data.extend_from_slice(&padding);
}

/// Implement the PKCS#7 padding scheme - unpad
pub fn pkcs7_unpad(data: &[u8]) -> Result<&[u8]> {
    let pad = *data
        .last()
        .ok_or_else(|| eyre!("Cannot unpad empty data."))?;
    ensure!(data.len() >= pad as usize, "Invalid padding for data.");
    Ok(&data[0..data.len() - pad as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7() {
        let padded = pkcs7("YELLOW SUBMARINE", 20);
        assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }

    #[test]
    fn test_pkcs7_into() {
        let mut data = b"YELLOW SUBMARINE".to_vec();
        pkcs7_into(&mut data, 20);
        assert_eq!(data, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }

    #[test]
    fn test_pkcs7_max_pad() {
        let padded = pkcs7("YELLOW SUBMARINE", 16);
        assert_eq!(
            padded,
            b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        );
    }

    #[test]
    fn test_pkcs7_into_max_pad() {
        let mut data = b"YELLOW SUBMARINE".to_vec();
        pkcs7_into(&mut data, 16);
        assert_eq!(
            data,
            b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        );
    }

    #[test]
    fn test_pkcs7_min_pad() {
        let padded = pkcs7("YELLOW SUBMARINE", 17);
        assert_eq!(padded, b"YELLOW SUBMARINE\x01");
    }

    #[test]
    fn test_pkcs7_into_min_pad() {
        let mut data = b"YELLOW SUBMARINE".to_vec();
        pkcs7_into(&mut data, 17);
        assert_eq!(data, b"YELLOW SUBMARINE\x01");
    }

    #[test]
    fn test_pkcs7_unpad() {
        let padded = pkcs7_unpad(b"YELLOW SUBMARINE\x04\x04\x04\x04");
        assert_eq!(padded.unwrap(), b"YELLOW SUBMARINE");
    }

    #[test]
    fn test_pkcs7_max_pad_unpad() {
        let padded = pkcs7_unpad(
            b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
        );
        assert_eq!(padded.unwrap(), b"YELLOW SUBMARINE");
    }

    #[test]
    fn test_pkcs7_min_pad_unpad() {
        let padded = pkcs7_unpad(b"YELLOW SUBMARINE\x01");
        assert_eq!(padded.unwrap(), b"YELLOW SUBMARINE");
    }
}
