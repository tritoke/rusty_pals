#![allow(clippy::erasing_op)]

use crate::encoding::DecodingError;
use crate::util::try_cast_as_arrays;

/// Base64 Alphabet from RFC4648
const TABLE: [u8; 64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Implements Base64 encoding based on RFC4648
/// ```
/// use rusty_pals::encoding::{Encodable, b64encode};
/// assert_eq!(b64encode("foobar"), "Zm9vYmFy");
/// assert_eq!(b"foobar".encode_b64() , "Zm9vYmFy");
/// ```
pub fn b64encode(input: impl AsRef<[u8]>) -> String {
    let data = input.as_ref();
    let encoded_len = (((data.len()) + 2) / 3) * 4;
    let mut encoded = String::with_capacity(encoded_len);

    for block in data.chunks(3) {
        // pack bytes into u32
        let a = *block
            .get(0)
            .expect("Chunks iterator will never yield an empty slice.");
        let b = *block.get(1).unwrap_or(&0);
        let c = *block.get(2).unwrap_or(&0);
        let bits = (a as usize) << 16 | (b as usize) << 8 | (c as usize);
        let pad = 3 - block.len();

        // unpack 6 bits at a time
        const MASK: usize = 0b111_111;
        let c1 = TABLE[(bits >> (3 * 6)) & MASK] as char;
        let c2 = TABLE[(bits >> (2 * 6)) & MASK] as char;
        let c3 = TABLE[(bits >> (1 * 6)) & MASK] as char;
        let c4 = TABLE[(bits >> (0 * 6)) & MASK] as char;

        // push characters and pad where appropriate
        encoded.push(c1);
        encoded.push(c2);
        encoded.push(if pad == 2 { '=' } else { c3 });
        encoded.push(if pad >= 1 { '=' } else { c4 });
    }

    encoded
}

/// Implements Base64 decoding based on RFC4648
/// ```
/// use rusty_pals::encoding::{Decodable, b64decode};
/// assert_eq!(b64decode("Zm9vYmFy").unwrap(), b"foobar");
/// assert_eq!("Zm9vYmFy".decode_b64().unwrap(), b"foobar");
/// ```
pub fn b64decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodingError> {
    let data = input.as_ref();
    let pad = data.ends_with(b"==") as usize + data.ends_with(b"=") as usize;

    let decoded_len = ((data.len() / 4) * 3) - pad;
    let mut decoded = Vec::with_capacity(decoded_len);

    for block in try_cast_as_arrays(data)? {
        let [b1, b2, b3, b4] = *block;
        let s1 = to_sextet(b1)?;
        let s2 = to_sextet(b2)?;
        let s3 = to_sextet(b3)?;
        let s4 = to_sextet(b4)?;

        // decoded the sextets into a bit block
        let bits: u32 = (s1 as u32) << (3 * 6)
            | (s2 as u32) << (2 * 6)
            | (s3 as u32) << (1 * 6)
            | (s4 as u32) << (0 * 6);

        // extract each character from the bits
        let c1 = (bits >> (8 * 2)) as u8;
        let c2 = (bits >> (8 * 1)) as u8;
        let c3 = (bits >> (8 * 0)) as u8;

        // handle padding
        if block[3] == b'=' {
            decoded.push(c1);
            if pad == 1 {
                decoded.push(c2)
            }
        } else {
            decoded.push(c1);
            decoded.push(c2);
            decoded.push(c3);
        }
    }

    Ok(decoded)
}

/// Translate a base64 character to a sextet
fn to_sextet(c: u8) -> Result<u8, DecodingError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 26 * 2),
        b'+' => Ok(62),
        b'/' => Ok(63),
        // treat pad character as zero
        b'=' => Ok(0),
        _ => Err(DecodingError::InvalidCharacter(c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        let test_vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];

        // base64 test vectors from RC4648
        for (t, c) in test_vectors {
            assert_eq!(b64encode(t), c.to_string());
        }
    }

    #[test]
    fn test_base64_decode() {
        let test_vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];

        // base64 test vectors from RC4648
        for (c, t) in test_vectors {
            assert_eq!(b64decode(t).unwrap().as_slice(), c.as_bytes());
        }
    }
}
