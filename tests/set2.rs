use rusty_pals::crypto::pad::PaddingError;
use rusty_pals::crypto::{
    aes::{decrypt, Aes128, Mode},
    pad,
};
use rusty_pals::encoding::{Decodable, DecodingError};
use rusty_pals::xor::XorError;
use std::str::Utf8Error;

#[derive(Debug, Clone)]
pub enum ChallengeError {
    DecodingError(DecodingError),
    XorError(XorError),
    PaddingError(PaddingError),
    Utf8Error(Utf8Error),
    Custom(String),
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ChallengeError {}

impl From<DecodingError> for ChallengeError {
    fn from(value: DecodingError) -> Self {
        Self::DecodingError(value)
    }
}

impl From<XorError> for ChallengeError {
    fn from(value: XorError) -> Self {
        Self::XorError(value)
    }
}

impl From<PaddingError> for ChallengeError {
    fn from(value: PaddingError) -> Self {
        Self::PaddingError(value)
    }
}

impl From<Utf8Error> for ChallengeError {
    fn from(value: Utf8Error) -> Self {
        Self::Utf8Error(value)
    }
}

impl From<String> for ChallengeError {
    fn from(value: String) -> Self {
        Self::Custom(value)
    }
}

pub type ChallengeResult<T> = Result<T, ChallengeError>;

#[test]
fn challenge9() -> ChallengeResult<()> {
    let input = "YELLOW SUBMARINE";
    let padded = pad::pkcs7(input, 20);
    assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");

    Ok(())
}

#[test]
fn challenge10() -> ChallengeResult<()> {
    let mut input = include_str!("files/10.txt").to_string();
    input.retain(|c| c != '\n');
    let data = input.decode_b64()?;
    let key = Aes128::new(b"YELLOW SUBMARINE");
    let iv = [0u8; 16];
    let mut dec = decrypt(data, key, iv, Mode::CBC);
    pad::pkcs7_unpad_owned(&mut dec)?;
    assert_eq!(dec, include_bytes!("files/10_correct.txt"));

    Ok(())
}

mod chal11 {
    use super::ChallengeResult;
    use rusty_pals::crypto::aes::Iv;
    use rusty_pals::crypto::{
        aes::{encrypt, Aes, Aes128, Mode},
        pad,
    };
    use rusty_pals::rand::{Rng32, XorShift32};
    use rusty_pals::util::{self, cast_as_arrays};

    fn encryption_oracle(
        rng: &mut XorShift32,
        input: impl AsRef<[u8]>,
    ) -> ChallengeResult<(bool, Vec<u8>)> {
        let n_before = 5 + (rng.gen() % 5) as usize;
        let n_after = 5 + (rng.gen() % 5) as usize;
        let mut data = rng.gen_bytes(n_before);
        data.extend_from_slice(input.as_ref());
        data.extend_from_slice(&rng.gen_bytes(n_after));
        pad::pkcs7_into(&mut data, Aes128::BLOCK_SIZE as u8);

        let key = Aes128::new(&rng.gen_array());
        let gen_ecb = rng.gen_bool();
        let enc = if gen_ecb {
            encrypt(data, key, Iv::Empty, Mode::ECB)
        } else {
            let iv = rng.gen_array();
            encrypt(data, key, iv, Mode::CBC)
        };

        Ok((gen_ecb, enc))
    }

    /// Detect the cipher mode by encrypting data which has at least 2 consecutive blocks with identical data.
    /// We can construct an input like this by passing a long run of the same data to the oracle.
    /// For ECB mode this will result in two consecutive blocks which encrypt to the same value.
    /// Whereas for CBC mode these blocks will encrypt differently due to the XOR operation mixing the bits.
    fn detect_mode(enc: Vec<u8>) -> bool {
        let blocks: &[[u8; 16]] = cast_as_arrays(enc.as_slice());
        util::has_duplicate(blocks)
    }

    #[test]
    fn challenge11() -> ChallengeResult<()> {
        let mut count_correct = 0;
        let num_rounds = 10000;
        let mut rng = XorShift32::new();
        for _ in 0..num_rounds {
            let (is_ecb, encrypted) = encryption_oracle(&mut rng, "A".repeat(43))?;
            let is_ecb_guess = detect_mode(encrypted);
            count_correct += (is_ecb == is_ecb_guess) as usize;
        }

        assert_eq!(count_correct, num_rounds);

        Ok(())
    }
}

mod chal12 {
    use super::ChallengeResult;
    use rusty_pals::crypto::aes::{encrypt, Aes, Aes128, Iv, Mode};
    use rusty_pals::crypto::oracle::EncryptionOracle;
    use rusty_pals::crypto::pad;
    use rusty_pals::encoding::Decodable;
    use rusty_pals::rand::{Rng32, XorShift32};
    use rusty_pals::util::{cast_as_array, cast_as_arrays};
    use std::collections::{HashMap, HashSet, VecDeque};

    #[test]
    fn challenge12() -> ChallengeResult<()> {
        let mut rng = XorShift32::new();
        let oracle = EcbOracle::new(&mut rng)?;

        let decoded = attack(oracle)?;
        let secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK";
        let secret = secret_b64.decode_b64()?;
        assert_eq!(decoded, secret);

        Ok(())
    }

    fn attack(oracle: impl EncryptionOracle) -> ChallengeResult<Vec<u8>> {
        const BLKSZ: usize = Aes128::BLOCK_SIZE;

        // Step 1. find the block size
        // we can feeding the cipher longer and longer strings until the length
        // of the returned ciphertext is becomes longer
        let empty_len = oracle.encrypt("").len();
        let mut i = 1;
        let block_size = loop {
            let l = oracle.encrypt("A".repeat(i)).len();
            if l != empty_len {
                break l - empty_len;
            }
            i += 1;
        };
        assert_eq!(block_size, BLKSZ);

        // Step 2: Detect the cipher mode
        // out input is of the form user-string || secret, so we can provide a string of 2*block_size
        // bytes to get two identical blocks at the beginning
        let enc = oracle.encrypt("A".repeat(2 * block_size));
        if enc[0..BLKSZ] != enc[BLKSZ..2 * BLKSZ] {
            panic!("Oracle is not using the ECB crypto mode.");
        }

        // Step 3/4: craft the block mappings
        let mut prefix_mapper = PrefixMapper::<BLKSZ>::new();
        let mut prefix = VecDeque::from(vec![b'A'; block_size]);
        prefix_mapper.compute_mappings(cast_as_array(prefix.make_contiguous()), &oracle)?;

        // Step 5: Match the output of the one-byte-short input
        let enc = oracle.encrypt(&prefix.as_slices().0[..BLKSZ - 1]);
        let block = &enc[..block_size];
        let decoded = prefix_mapper
            .get(block)
            .expect("Failed to recover byte from secret.");

        // Step 6: Repeat :)
        let mut dec = vec![decoded];
        for i in 2..empty_len {
            prefix.pop_front();
            prefix.pop_back();
            prefix.push_back(dec.last().copied().unwrap());
            prefix.push_back(b'A');
            prefix_mapper.compute_mappings(cast_as_array(prefix.make_contiguous()), &oracle)?;

            let block_offset = i / 16;
            let enc = oracle.encrypt(&prefix.as_slices().0[..BLKSZ - (i % BLKSZ)]);
            let blocks: &[[u8; 16]] = cast_as_arrays(&enc[..]);
            let block = &blocks[block_offset];
            if let Some(decoded) = prefix_mapper.get(block) {
                dec.push(decoded);
            } else {
                break;
            }
        }

        pad::pkcs7_unpad_owned(&mut dec)?;
        Ok(dec)
    }

    /// Struct representing an Oracle performing AES-ECB-128 Encryption
    #[derive(Debug)]
    struct EcbOracle {
        key: Aes128,
        secret: Vec<u8>,
    }

    impl EcbOracle {
        fn new(rng: &mut XorShift32) -> ChallengeResult<Self> {
            let secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK";
            let secret = secret_b64.decode_b64()?;
            let key = Aes128::new(&rng.gen_array());
            Ok(Self { key, secret })
        }
    }

    impl EncryptionOracle for EcbOracle {
        fn encrypt(&self, data: impl AsRef<[u8]>) -> Vec<u8> {
            let mut data = data.as_ref().to_vec();
            // Construct your-string || unknown-string
            data.extend_from_slice(&self.secret);
            pad::pkcs7_into(&mut data, Aes128::BLOCK_SIZE as u8);

            // Construct ECB(your-string || unknown-string, random-key)
            encrypt(data, self.key, Iv::Empty, Mode::ECB)
        }
    }

    /// A struct storing the mappings for all the prefixes, ensuring they are only calculated once
    #[derive(Default, Debug, Clone)]
    pub(super) struct PrefixMapper<const BLKSZ: usize> {
        mapping: HashMap<[u8; BLKSZ], u8>,
        prefixes: HashSet<[u8; BLKSZ]>,
    }

    impl<const BLKSZ: usize> PrefixMapper<BLKSZ> {
        pub(super) fn new() -> Self {
            Default::default()
        }

        /// Compute the mappings for a given prefix
        pub(super) fn compute_mappings(
            &mut self,
            prefix: &[u8; BLKSZ],
            oracle: &impl EncryptionOracle,
        ) -> ChallengeResult<()> {
            let mut block = *prefix;
            // ignore the last byte of the prefix
            block[BLKSZ - 1] = 0;

            // check wether we have already calculated these prefixes
            if !self.prefixes.insert(block) {
                return Ok(());
            }

            for b in u8::MIN..=u8::MAX {
                block[BLKSZ - 1] = b;
                let mut enc = oracle.encrypt(block);
                enc.truncate(BLKSZ);
                let arr: &[u8; BLKSZ] = cast_as_array(&enc[..]);
                self.mapping.insert(*arr, b);
            }

            Ok(())
        }

        /// Get elements from the mapping
        pub(super) fn get(&self, block: &[u8]) -> Option<u8> {
            self.mapping.get(block).copied()
        }
    }
}

mod chal13 {
    use super::ChallengeResult;
    use crate::ChallengeError;
    use rusty_pals::crypto::aes::{decrypt, encrypt, Aes, Aes128, Iv, Mode};
    use rusty_pals::crypto::pad::{pkcs7_into, pkcs7_unpad_owned};
    use rusty_pals::encoding::Encodable;
    use rusty_pals::rand::{Rng32, XorShift32};
    use std::fmt;
    use std::fmt::{Formatter, Write};
    use std::str::FromStr;

    #[derive(Default, Debug, Clone)]
    struct CookieJar {
        cookies: Vec<(String, String)>,
    }

    impl CookieJar {
        fn new() -> Self {
            Default::default()
        }

        fn add_cookie(&mut self, k: impl AsRef<str>, v: impl AsRef<str>) {
            self.cookies
                .push((k.as_ref().to_string(), v.as_ref().to_string()));
        }

        fn get(&self, k: &str) -> Option<&str> {
            self.cookies
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        }
    }

    impl FromStr for CookieJar {
        type Err = ChallengeError;

        fn from_str(s: &str) -> ChallengeResult<Self> {
            let mut cookie_jar = CookieJar::new();

            for cookie in s.split('&') {
                if let Some((k, v)) = cookie.split_once('=') {
                    cookie_jar.add_cookie(k, v);
                } else {
                    return Err(format!("Failed to parse key/value pair {cookie:?}").into());
                }
            }

            Ok(cookie_jar)
        }
    }

    impl fmt::Display for CookieJar {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let mut first = true;
            for (k, v) in self.cookies.iter() {
                if first {
                    first = false;
                } else {
                    f.write_char('&')?;
                }
                write!(f, "{k}={v}")?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_cookie_jar() {
        let input = "foo=bar&baz=qux&zap=zazzle";
        let jar: CookieJar = input.parse().unwrap();

        assert_eq!(
            jar.cookies,
            [
                ("foo".to_string(), "bar".to_string()),
                ("baz".to_string(), "qux".to_string()),
                ("zap".to_string(), "zazzle".to_string())
            ]
        );
        assert_eq!(jar.get("foo"), Some("bar"));
        let s = format!("{}", jar);
        assert_eq!(s, input);
    }

    fn profile_for(email: &str) -> String {
        // strip illegal characters
        let mut email = email.to_string();
        email.retain(|c| c != '&' && c != '=');

        let mut cookie_jar = CookieJar::new();

        cookie_jar.add_cookie("email", email);
        cookie_jar.add_cookie("uid", "10");
        cookie_jar.add_cookie("role", "user");

        format!("{}", cookie_jar)
    }

    #[test]
    fn test_profile_for() {
        assert_eq!(
            profile_for("foo@bar.com"),
            "email=foo@bar.com&uid=10&role=user"
        );
    }

    #[test]
    fn test_profile_for_sanitizes_illegal_input() {
        assert_eq!(
            profile_for("foo@bar.com&role=admin"),
            "email=foo@bar.comroleadmin&uid=10&role=user"
        );
    }

    #[derive(Debug)]
    struct ProfileManager {
        key: Aes128,
    }

    impl ProfileManager {
        fn new(rng: &mut XorShift32) -> Self {
            Self {
                key: Aes128::new(&rng.gen_array()),
            }
        }

        fn encrypt_profile(&self, email: impl AsRef<str>) -> Vec<u8> {
            let mut data = profile_for(email.as_ref()).into_bytes();
            pkcs7_into(&mut data, Aes128::BLOCK_SIZE as u8);
            encrypt(data, self.key, Iv::Empty, Mode::ECB)
        }

        fn decrypt_profile(&self, data: Vec<u8>) -> ChallengeResult<CookieJar> {
            let mut dec = decrypt(data, self.key, Iv::Empty, Mode::ECB);
            pkcs7_unpad_owned(&mut dec)?;
            let profile = String::from_utf8(dec).expect("Failed to decrypt -");
            profile.parse()
        }
    }

    #[test]
    fn challenge13() -> ChallengeResult<()> {
        let mut rng = XorShift32::new();
        let mut profile_manager = ProfileManager::new(&mut rng);

        let enc_profile = attack(&mut profile_manager)?;
        let cookie_jar = profile_manager.decrypt_profile(enc_profile)?;

        // assert that we have overwritten the role and that we have preserved our email
        assert_eq!(cookie_jar.get("role"), Some("admin"));

        Ok(())
    }

    fn attack(pm: &mut ProfileManager) -> ChallengeResult<Vec<u8>> {
        // Step 1: Get the plaintext for the email we are creating a profile for
        let plaintext = profile_for("");

        // Step 2: find the position where we can encrypt a block of 16 characters
        let input_start = plaintext
            .find("email=")
            .expect("Plaintext didn't contain email=, unable to find position")
            + "email=".len();
        let padding = if input_start % Aes128::BLOCK_SIZE != 0 {
            Aes128::BLOCK_SIZE - (input_start % Aes128::BLOCK_SIZE)
        } else {
            0
        };
        let controlled_block = (input_start + padding) / 16;

        // Step 3: encrypt an admin + padding chunk
        let mut admin_chunk = b"admin".to_vec();
        pkcs7_into(&mut admin_chunk, Aes128::BLOCK_SIZE as u8);
        let enc = pm.encrypt_profile(format!(
            "{}{}",
            "A".repeat(padding),
            std::str::from_utf8(&admin_chunk)?
        ));
        let forged_chunk = &enc[controlled_block * 16..(controlled_block + 1) * 16];
        forged_chunk.encode_hex();

        // Step 4: construct a messsage padded such that role= lies just before a chunk boundary
        let user_pos = &plaintext
            .find("user")
            .expect("Plaintext didn't contain \"user\", unable to find position");
        let padding = Aes128::BLOCK_SIZE - (user_pos % Aes128::BLOCK_SIZE);
        let mut enc = pm.encrypt_profile("A".repeat(padding));

        // Step 5: replace the final chunk with our chunk
        enc.truncate(enc.len() - Aes128::BLOCK_SIZE);
        enc.extend_from_slice(forged_chunk);

        Ok(enc)
    }
}

mod chal14 {
    use super::chal12::PrefixMapper;
    use super::ChallengeResult;
    use rusty_pals::crypto::aes::Iv;
    use rusty_pals::crypto::{
        aes::{encrypt, Aes, Aes128, Mode},
        oracle::EncryptionOracle,
        pad,
    };
    use rusty_pals::encoding::Decodable;
    use rusty_pals::rand::{Rng32, XorShift32};
    use rusty_pals::util::{cast_as_array, cast_as_arrays};
    use std::collections::VecDeque;

    #[derive(Debug)]
    struct EcbOracle {
        key: Aes128,
        prefix: Vec<u8>,
        secret: Vec<u8>,
    }

    impl EcbOracle {
        fn new(rng: &mut XorShift32) -> ChallengeResult<Self> {
            let secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK";
            let secret = secret_b64.decode_b64()?;
            let key = Aes128::new(&rng.gen_array());
            let prefix_len = 20 + (rng.gen() % 30);
            let prefix = rng.gen_bytes(prefix_len as usize);
            Ok(Self {
                key,
                prefix,
                secret,
            })
        }
    }

    impl EncryptionOracle for EcbOracle {
        fn encrypt(&self, attacker_controlled: impl AsRef<[u8]>) -> Vec<u8> {
            // Construct random-prefix || attacker-controlled || target-bytes
            let mut data = self.prefix.clone();
            data.extend_from_slice(attacker_controlled.as_ref());
            data.extend_from_slice(&self.secret);
            pad::pkcs7_into(&mut data, Aes128::BLOCK_SIZE as u8);

            // Construct ECB(random-prefix || attacker-controlled || target-bytes, random-key)
            encrypt(data, self.key, Iv::Empty, Mode::ECB)
        }
    }

    /// Struct to wrap the original crypto oracle into one we can use with the prefix mapper
    #[derive(Debug)]
    struct OracleWrapper<T: EncryptionOracle> {
        inner_oracle: T,
        padding: Vec<u8>,
        offset: usize,
    }

    impl<T: EncryptionOracle> OracleWrapper<T> {
        fn new(oracle: T, padding: Vec<u8>, offset: usize) -> Self {
            Self {
                inner_oracle: oracle,
                padding,
                offset,
            }
        }
    }

    impl<T: EncryptionOracle> EncryptionOracle for OracleWrapper<T> {
        fn encrypt(&self, data: impl AsRef<[u8]>) -> Vec<u8> {
            let mut d = self.padding.clone();
            d.extend_from_slice(data.as_ref());
            self.inner_oracle.encrypt(d)[self.offset..].to_vec()
        }
    }

    #[test]
    fn challenge14() -> ChallengeResult<()> {
        let mut rng = XorShift32::new();
        let oracle = EcbOracle::new(&mut rng)?;

        let decoded = attack(oracle)?;
        let secret_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
            YnkK";
        let secret = secret_b64.decode_b64()?;
        assert_eq!(decoded, secret);

        Ok(())
    }

    fn attack(oracle: impl EncryptionOracle) -> ChallengeResult<Vec<u8>> {
        const BLKSZ: usize = Aes128::BLOCK_SIZE;

        // Step 1. find the block size
        // we can feeding the cipher longer and longer strings until the length
        // of the returned ciphertext is becomes longer
        let empty_len = oracle.encrypt("").len();
        let mut i = 1;
        let block_size = loop {
            let l = oracle.encrypt("A".repeat(i)).len();
            if l != empty_len {
                break l - empty_len;
            }
            i += 1;
        };
        assert_eq!(block_size, BLKSZ);

        // Step 2: Detect the cipher mode
        let enc = oracle.encrypt("A".repeat(3 * block_size));
        let blocks: &[[u8; 16]] = cast_as_arrays(&enc);

        let pos = blocks
            .iter()
            .zip(blocks.iter().skip(1))
            .position(|(a, b)| a == b)
            .expect("Oracle is not using the ECB crypto mode.");

        // Step 2.5 work out padding and offsets to ignore the prefixed data
        let controlled_block = pos * block_size;
        let mut padding = Vec::new();
        // keep pushing characters into the padding until the controlled block matches the original one
        loop {
            let mut s = padding.clone();
            s.extend_from_slice(&[b'A'].repeat(16));
            let new_enc = oracle.encrypt(s);
            let block = &new_enc[controlled_block..controlled_block + block_size];
            let correct_block = &enc[controlled_block..controlled_block + block_size];
            if block == correct_block {
                break;
            } else {
                padding.push(b'A');
            }
        }

        let oracle = OracleWrapper::new(oracle, padding.clone(), controlled_block);

        // Step 3/4: craft the block mappings
        let mut prefix_mapper = PrefixMapper::<BLKSZ>::new();
        let mut prefix = VecDeque::from(vec![b'A'; block_size]);
        prefix_mapper.compute_mappings(cast_as_array(prefix.make_contiguous()), &oracle)?;

        // Step 5: Match the output of the one-byte-short input
        let mut data = Vec::new();
        data.extend_from_slice(&prefix.as_slices().0[..BLKSZ - 1]);
        let enc = oracle.encrypt(&data);
        let block = &enc[..block_size];
        let decoded = prefix_mapper
            .get(block)
            .expect("Failed to recover byte from secret.");

        // Step 6: Repeat :)
        let mut dec = vec![decoded];
        for i in 2..empty_len {
            prefix.pop_front();
            prefix.pop_back();
            prefix.push_back(dec.last().copied().unwrap());
            prefix.push_back(b'A');
            prefix_mapper.compute_mappings(cast_as_array(prefix.make_contiguous()), &oracle)?;

            let block_offset = i / 16;
            let enc = oracle.encrypt(&prefix.as_slices().0[..BLKSZ - (i % BLKSZ)]);
            let blocks: &[[u8; 16]] = cast_as_arrays(&enc[..]);
            let block = &blocks[block_offset];
            if let Some(decoded) = prefix_mapper.get(block) {
                dec.push(decoded);
            } else {
                break;
            }
        }

        pad::pkcs7_unpad_owned(&mut dec)?;
        Ok(dec)
    }
}

#[test]
#[rustfmt::skip]
fn challenge15() {
    assert_eq!(pad::pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04").unwrap(), b"ICE ICE BABY");
    assert!(pad::pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05").is_err());
    assert!(pad::pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04").is_err());
}

mod chall16 {
    use super::ChallengeResult;
    use rusty_pals::crypto::{
        aes::{decrypt, encrypt, Aes, Aes128, Mode},
        pad,
    };
    use rusty_pals::rand::{Rng32, XorShift32};
    use rusty_pals::util::cast_as_array;
    use std::io::Write;

    #[derive(Debug)]
    struct Challenge {
        key: Aes128,
        rng: XorShift32,
    }

    impl Challenge {
        fn new() -> Self {
            let mut rng = XorShift32::new();
            Self {
                key: Aes128::new(&rng.gen_array()),
                rng,
            }
        }

        fn encrypt(&mut self, data: impl AsRef<[u8]>) -> Vec<u8> {
            let mut s = b"comment1=cooking%20MCs;userdata=".to_vec();
            for c in data.as_ref() {
                match c {
                    b'=' | b';' => write!(s, "%{c:02X}").unwrap(),
                    _ => s.push(*c),
                }
            }
            s.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
            pad::pkcs7_into(&mut s, Aes128::BLOCK_SIZE as u8);
            let iv = self.rng.gen_array();
            let mut enc = iv.to_vec();
            enc.extend_from_slice(&encrypt(s, self.key, iv, Mode::CBC));
            enc
        }

        fn decrypt(&self, data: impl AsRef<[u8]>) -> bool {
            let data = data.as_ref();
            let (iv, data) = data.split_at(Aes128::BLOCK_SIZE);
            let mut dec = decrypt(data, self.key, *cast_as_array(iv), Mode::CBC);
            if pad::pkcs7_unpad_owned(&mut dec).is_err() {
                return false;
            }
            let text = String::from_utf8_lossy(&dec);

            let needle = ";admin=true;";
            text.contains(needle)
        }
    }

    #[test]
    fn test_correct_output_forbidden() -> ChallengeResult<()> {
        let mut chall = Challenge::new();
        let enc = chall.encrypt(";admin=true;");
        assert!(!chall.decrypt(enc));

        Ok(())
    }

    #[test]
    fn challenge16() -> ChallengeResult<()> {
        let mut chall = Challenge::new();

        let manipulated = attack(&mut chall);
        assert!(chall.decrypt(manipulated));

        Ok(())
    }

    fn attack(chal: &mut Challenge) -> Vec<u8> {
        let offset = 2 * Aes128::BLOCK_SIZE;
        let input = "A".repeat(Aes128::BLOCK_SIZE * 2);
        let mut ct = chal.encrypt(&input);

        let desired_output = b";admin=true;";
        for (i, (inp, des_out)) in input
            .as_bytes()
            .iter()
            .zip(desired_output.iter())
            .enumerate()
        {
            ct[i + offset] ^= inp ^ des_out;
        }

        ct
    }
}
