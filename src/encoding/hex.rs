use crate::util::try_cast_as_arrays;
use anyhow::{anyhow, ensure, Result};

/// Parse an input string as encoding
/// ```
/// use rusty_pals::encoding::parse_hex;
/// assert_eq!(parse_hex("1234").unwrap(), &[0x12, 0x34]);
/// ```
pub fn parse_hex(input: &str) -> Result<Vec<u8>> {
    ensure!(input.len() % 2 == 0, "Input string must be an even length.");
    try_cast_as_arrays(input.as_bytes())?
        .iter()
        .map(|&[h, l]| Ok(h2b(h)? << 4 | h2b(l)?))
        .collect()
}

/// Turn a slice of bytes into a hex encoded string
/// ```
/// use rusty_pals::encoding::{Encodable, to_hex};
/// assert_eq!(to_hex([0x12, 0x34, 0x56, 0x78]), "12345678");
/// assert_eq!([0x12, 0x34, 0x56, 0x78].encode_hex(), "12345678");
/// ```
pub fn to_hex(input: impl AsRef<[u8]>) -> String {
    let mut utf8 = Vec::new();
    utf8.extend(input.as_ref().iter().copied().flat_map(b2h));

    // SAFETY: every character in the string is produced by b2h
    //         b2h uses a table of ASCII byte literals to encode
    //         its output, this means the bytes are always valid UTF-8
    unsafe { String::from_utf8_unchecked(utf8) }
}

/// Convert a byte from a encoding character to its value in encoding
fn h2b(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        x => Err(anyhow!(
            "Unrecognised encoding character {x:?} - {:?}",
            x as char
        )),
    }
}

/// Convert a byte into a pair of bytes representing it's encoding value
fn b2h(h: u8) -> [u8; 2] {
    #[rustfmt::skip]
    const TABLE: [u8; 16] = [
        b'0', b'1', b'2', b'3',
        b'4', b'5', b'6', b'7',
        b'8', b'9', b'a', b'b',
        b'c', b'd', b'e', b'f',
    ];

    let hi = TABLE[(h >> 4) as usize];
    let lo = TABLE[(h & 0b1111) as usize];
    [hi, lo]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h2b() {
        for (b, v) in (b'0'..=b'9').zip(0..=9) {
            assert_eq!(h2b(b).unwrap(), v);
        }

        for (b, v) in (b'A'..=b'F').zip(10..=15) {
            assert_eq!(h2b(b).unwrap(), v);
        }

        for (b, v) in (b'a'..=b'f').zip(10..=15) {
            assert_eq!(h2b(b).unwrap(), v);
        }
    }

    #[test]
    fn test_h2b_fails() {
        assert!(h2b(b'G').is_err());
        assert!(h2b(b'*').is_err());
        assert!(h2b(b'#').is_err());
    }

    #[test]
    fn test_b2h() {
        for h in u8::MIN..=u8::MAX {
            let s = format!("{h:02x}").into_bytes();
            let a = s[0];
            let b = s[1];
            assert_eq!(b2h(h), [a, b]);
        }
    }

    #[test]
    fn test_parse_hex() {
        let correct = b"beans".to_vec();
        assert_eq!(parse_hex("6265616e73").unwrap(), correct);
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(
            to_hex(&[0x62, 0x65, 0x61, 0x6e, 0x73]),
            "6265616e73".to_owned()
        );
    }

    #[test]
    fn test_parse_hex_fails_bad_char() {
        assert!(parse_hex("6z").is_err());
    }
}
