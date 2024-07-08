use std::string::FromUtf8Error;

use crypto_core::xor::XorError;

mod helpers;
use helpers::*;

#[derive(Debug, Clone)]
pub enum ChallengeError {
    XorError(XorError),
    FromUtf8Error(FromUtf8Error),
}

impl_error_boilerplate!(ChallengeError);
impl_error_from_types!(ChallengeError: XorError, FromUtf8Error);

pub type ChallengeResult<T> = Result<T, ChallengeError>;

#[repr(align(4))]
#[derive(Clone, Copy)]
struct AlignedBytes([u8; 20]);

impl From<AlignedBytes> for crypto_core::crypto::shs::Sha1Digest {
    fn from(bytes: AlignedBytes) -> Self {
        Self(unsafe { std::mem::transmute(bytes) })
    }
}

mod chall25 {
    use crate::ChallengeResult;
    use crypto_core::crypto::aes::{decrypt, encrypt, Aes128, Iv, Mode};
    use crypto_core::rand::{Rng32, XorShift32};
    use crypto_core::xor::{xor_blocks, xor_with_key};

    #[derive(Debug)]
    struct Challenge {
        key: Aes128,
        nonce: Iv,
        ciphertext: Vec<u8>,
    }

    impl Challenge {
        fn new() -> Self {
            let mut rng = XorShift32::new();
            let key = Aes128::new(&rng.gen_array());
            let nonce = Iv::Nonce(u64::from_be_bytes(rng.gen_array()));
            let ciphertext = encrypt(include_str!("files/7_correct.txt"), key, nonce, Mode::CTR);

            Self {
                key,
                nonce,
                ciphertext,
            }
        }

        fn edit(&self, offset: usize, newtext: impl AsRef<[u8]>) -> Vec<u8> {
            let mut dec = decrypt(&self.ciphertext, self.key, self.nonce, Mode::CTR);
            for (d, n) in dec.iter_mut().skip(offset).zip(newtext.as_ref().iter()) {
                *d = *n;
            }

            encrypt(dec, self.key, self.nonce, Mode::CTR)
        }
    }

    #[test]
    fn challenge25() -> ChallengeResult<()> {
        let chall = Challenge::new();
        let pt = attack(&chall)?;
        assert_eq!(pt, include_str!("files/7_correct.txt"));

        Ok(())
    }

    fn attack(chall: &Challenge) -> ChallengeResult<String> {
        let ct = chall.ciphertext.clone();
        let key_xor_a = chall.edit(0, vec![b'A'; ct.len()]);
        let keystream = xor_with_key(key_xor_a, "A")?;
        Ok(String::from_utf8(xor_blocks(ct, keystream)?)?)
    }
}

mod chall26 {
    use crate::ChallengeResult;
    use crypto_core::crypto::aes::{decrypt, encrypt, Aes128, Mode};
    use crypto_core::rand::{Rng32, XorShift32};
    use crypto_core::util::cast_as_array;
    use std::io::Write;
    use std::mem;

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
            let nonce_bytes = self.rng.gen_array();
            let nonce = u64::from_be_bytes(nonce_bytes);
            let mut enc = nonce_bytes.to_vec();
            enc.extend_from_slice(&encrypt(s, self.key, nonce, Mode::CTR));
            enc
        }

        fn decrypt(&self, data: impl AsRef<[u8]>) -> bool {
            let data = data.as_ref();
            let (nonce_bytes, data) = data.split_at(mem::size_of::<u64>());
            let nonce = u64::from_be_bytes(*cast_as_array(nonce_bytes));
            let dec = decrypt(data, self.key, nonce, Mode::CTR);
            let text = String::from_utf8_lossy(&dec);

            let needle = ";admin=true;";
            text.contains(needle)
        }
    }

    #[test]
    fn challenge26() -> ChallengeResult<()> {
        let mut chall = Challenge::new();

        let manipulated = attack(&mut chall);
        assert!(chall.decrypt(manipulated));

        Ok(())
    }

    fn attack(chal: &mut Challenge) -> Vec<u8> {
        let desired_output = b";admin=true;";
        let input = "A".repeat(desired_output.len());
        let mut ct = chal.encrypt(&input);
        let offset = 32 + mem::size_of::<u64>();

        for (c, (i, d)) in ct
            .iter_mut()
            .skip(offset)
            .zip(input.as_bytes().iter().zip(desired_output.iter()))
        {
            *c ^= i ^ d;
        }

        ct
    }
}

mod chall27 {
    use crypto_core::crypto::{
        aes::{decrypt, encrypt, Aes, Aes128, Mode},
        pad,
    };
    use crypto_core::rand::{Rng32, XorShift32};
    use crypto_core::util::cast_as_arrays;
    use crypto_core::xor::xor_block_simd;
    use std::io::Write;
    use std::string::FromUtf8Error;

    #[derive(Debug)]
    struct Challenge {
        key: Aes128,
        iv: [u8; 16],
    }

    impl Challenge {
        fn new() -> Self {
            let iv = XorShift32::new().gen_array();
            Self {
                key: Aes128::new(&iv),
                iv,
            }
        }

        fn encrypt(&self, data: impl AsRef<[u8]>) -> Vec<u8> {
            let mut s = b"comment1=cooking%20MCs;userdata=".to_vec();
            for c in data.as_ref() {
                match c {
                    b'=' | b';' => write!(s, "%{c:02X}").unwrap(),
                    _ => s.push(*c),
                }
            }
            s.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
            pad::pkcs7_into(&mut s, Aes128::BLOCK_SIZE as u8);
            encrypt(s, self.key, self.iv, Mode::CBC)
        }

        fn decrypt(&self, data: impl AsRef<[u8]>) -> Result<bool, Vec<u8>> {
            let data = data.as_ref();
            let dec = decrypt(data, self.key, self.iv, Mode::CBC);
            let needle = ";admin=true;";
            String::from_utf8(dec)
                .map(|text| text.contains(needle))
                .map_err(FromUtf8Error::into_bytes)
        }
    }

    #[test]
    fn challenge27() {
        let chall = Challenge::new();
        let key = attack(&chall);
        assert_eq!(key, chall.iv);
    }

    fn attack(chall: &Challenge) -> [u8; 16] {
        let ct = chall.encrypt("");
        let ct_chunks = cast_as_arrays(&ct);
        let malicious = [ct_chunks[0], [0u8; 16], ct_chunks[0]].concat();
        let plain = chall.decrypt(malicious).unwrap_err();
        let plain_chunks = cast_as_arrays(&plain);
        xor_block_simd(&plain_chunks[0], &plain_chunks[2])
    }
}

mod chall28 {
    use crypto_core::crypto::shs::Sha1Digest;
    use crypto_core::crypto::{shs::Sha1, Hasher};
    use crypto_core::rand::{Rng32, XorShift32};
    use std::marker::PhantomData;

    pub(super) struct Challenge<H: Hasher> {
        key: [u8; 20],
        _h: PhantomData<H>,
    }

    impl<H: Hasher> Challenge<H> {
        pub(super) fn new() -> Self {
            Self {
                key: XorShift32::new().gen_array(),
                _h: Default::default(),
            }
        }

        pub(super) fn mac(&self, message: impl AsRef<[u8]>) -> H::Digest {
            let mut hasher = H::new();
            hasher.update(self.key);
            hasher.update(message.as_ref());
            hasher.finalize();
            hasher.digest()
        }

        pub(super) fn is_message_valid(&self, message: impl AsRef<[u8]>, mac: H::Digest) -> bool
        where
            <H as Hasher>::Digest: PartialEq,
        {
            self.mac(message) == mac
        }
    }

    #[test]
    fn challenge28() {
        let chall: Challenge<Sha1> = Challenge::new();
        let mut data = b"I should probably write some cool movie quote here for some future dev to find and smile at, but alas I can't be arsed.".to_vec();
        let mac = chall.mac(&data);
        assert!(chall.is_message_valid(&data, mac));
        data[5] = b'1';
        assert!(!chall.is_message_valid(&data, mac));
        assert!(!chall.is_message_valid(&data, Sha1Digest([1, 2, 3, 4, 5])));
    }
}

mod chall29 {
    use super::chall28::Challenge;
    use crypto_core::crypto::{shs::Sha1, Hasher};

    type Digest = <Sha1 as Hasher>::Digest;

    fn attack(data: &[u8], mac: Digest) -> (Vec<u8>, Digest) {
        let mut new_data = data.to_vec();
        const ADMIN_STRING: &[u8] = b";admin=true";
        const MAC_KEY_SIZE: u64 = 20;

        // pad data with the original SHA1 padding
        let msg_len = data.len() as u64 * 8 + MAC_KEY_SIZE * 8;
        new_data.push(0x80);
        let k = (-(msg_len as i64) - 64 - 8).rem_euclid(512);
        new_data.extend_from_slice(&vec![0; k as usize / 8]);
        new_data.extend_from_slice(&msg_len.to_be_bytes());

        // remember the processed length for later
        let processed_len = new_data.len();

        // append the malicious string
        new_data.extend_from_slice(ADMIN_STRING);

        // setup the hasher to receive the new string
        let mut hasher = Sha1::from(mac);
        hasher.set_message_len(processed_len as u64 * 8 + MAC_KEY_SIZE * 8);

        // calculate the hash from this new appended data
        hasher.update(ADMIN_STRING);
        hasher.finalize();

        let new_mac = hasher.digest();

        (new_data, new_mac)
    }

    #[test]
    fn challenge29() {
        let chall: Challenge<Sha1> = Challenge::new();
        let data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let mac = chall.mac(data);
        let (new_data, new_mac) = attack(data, mac);
        assert!(new_data.ends_with(b";admin=true"));
        assert!(chall.is_message_valid(new_data, new_mac));
    }
}

mod chall30 {
    use super::chall28::Challenge;
    use crypto_core::crypto::{md4::Md4, Hasher};

    type Digest = <Md4 as Hasher>::Digest;

    fn attack(data: &[u8], mac: Digest) -> (Vec<u8>, Digest) {
        let mut new_data = data.to_vec();
        const ADMIN_STRING: &[u8] = b";admin=true";
        const MAC_KEY_SIZE: u64 = 20;

        // pad data with the original Md4 padding
        let msg_len = data.len() as u64 * 8 + MAC_KEY_SIZE * 8;
        new_data.push(0x80);
        let k = (-(msg_len as i64) - 64 - 8).rem_euclid(512);
        new_data.extend_from_slice(&vec![0; k as usize / 8]);
        new_data.extend_from_slice(&msg_len.to_le_bytes());

        // remember the processed length for later
        let processed_len = new_data.len();

        // append the malicious string
        new_data.extend_from_slice(ADMIN_STRING);

        // setup the hasher to receive the new string
        let mut hasher = Md4::from(mac);
        hasher.set_message_len(processed_len as u64 * 8 + MAC_KEY_SIZE * 8);

        // calculate the hash from this new appended data
        hasher.update(ADMIN_STRING);
        hasher.finalize();

        let new_mac = hasher.digest();

        (new_data, new_mac)
    }

    #[test]
    fn challenge30() {
        let chall: Challenge<Md4> = Challenge::new();
        let data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let mac = chall.mac(data);
        let (new_data, new_mac) = attack(data, mac);
        assert!(new_data.ends_with(b";admin=true"));
        assert!(chall.is_message_valid(new_data, new_mac));
    }
}

mod chall31 {
    use super::AlignedBytes;
    use crypto_core::crypto::hmac::Hmac;
    use crypto_core::crypto::shs::{Sha1, Sha1Digest};
    use crypto_core::rand::{Rng32, XorShift32};
    use std::time::Duration;

    struct Challenge {
        hmacer: Hmac<Sha1>,
    }

    impl Challenge {
        fn new() -> Self {
            Self {
                hmacer: Hmac::new("Be gay do crimes!!!"),
            }
        }

        /// cba with sleeps, just return the number of correct bytes as a float with some noise added
        fn insecure_compare(a: &[u8], b: &[u8]) -> (bool, Duration) {
            let mut time_slept = Duration::default();
            let mut equal = true;
            let mut rng = XorShift32::new();

            for (c1, c2) in a.iter().zip(b.iter()) {
                if c1 != c2 {
                    equal = false;
                    break;
                }

                // Add 50ms plus some noise up to 0xFFF - 4095us = 4ms
                time_slept +=
                    Duration::from_millis(50) + Duration::from_micros(rng.gen() as u64 & 0xFFF);
            }

            (equal, time_slept)
        }

        fn challenge(&self, file: &[u8], signature: Sha1Digest) -> (u32, Duration) {
            let mac = self.hmacer.mac(file);
            let (equal, duration) = Self::insecure_compare(mac.as_ref(), signature.as_ref());
            if equal {
                (200, duration)
            } else {
                (500, duration)
            }
        }
    }

    fn attack(chall: &Challenge, data: &[u8]) -> Sha1Digest {
        let mut recovered = AlignedBytes([0u8; 20]);

        for i in 0..recovered.0.len() {
            let (byte, _time) = (u8::MIN..=u8::MAX)
                .map(|b| {
                    recovered.0[i] = b;
                    (b, chall.challenge(data, Sha1Digest::from(recovered)).1)
                })
                .max_by_key(|(_, cmp_time)| *cmp_time)
                .expect("Max on non-empty iterator always returns a value");
            recovered.0[i] = byte;
        }

        Sha1Digest::from(recovered)
    }

    #[test]
    fn challenge31() {
        let (equal, time) = Challenge::insecure_compare(b"cock", b"cook");
        assert!(!equal);
        assert!(time >= Duration::from_millis(100));
        assert!(time <= Duration::from_millis(100) + Duration::from_micros(0xFFF * 2));

        let chall = Challenge::new();
        let data = b"My name is jeff and I can count to 10!";
        let sig = attack(&chall, data);
        assert_eq!(chall.challenge(data, sig).0, 200);
    }
}

mod chall32 {
    use super::AlignedBytes;
    use crypto_core::crypto::hmac::Hmac;
    use crypto_core::crypto::shs::{Sha1, Sha1Digest};
    use crypto_core::rand::{Rng32, XorShift32};
    use std::time::Duration;

    const COMPARE_TIME: Duration = Duration::from_millis(5);

    struct Challenge {
        hmacer: Hmac<Sha1>,
    }

    impl Challenge {
        fn new() -> Self {
            Self {
                hmacer: Hmac::new("Be gay do crimes!!!"),
            }
        }

        /// cba with sleeps, just return the number of correct bytes as a float with some noise added
        fn insecure_compare(a: &[u8], b: &[u8]) -> (bool, Duration) {
            let mut time_slept = COMPARE_TIME;
            let mut equal = true;
            let mut rng = XorShift32::new();

            for (c1, c2) in a.iter().zip(b.iter()) {
                if c1 != c2 {
                    equal = false;
                    break;
                }

                // Add 5ms plus some noise up to 0x3FF - 1023us = 1ms
                time_slept += COMPARE_TIME + Duration::from_micros(rng.gen() as u64 & 0x3FF);
            }

            (equal, time_slept)
        }

        fn challenge(&self, file: &[u8], signature: Sha1Digest) -> (u32, Duration) {
            let mac = self.hmacer.mac(file);
            let (equal, duration) = Self::insecure_compare(mac.as_ref(), signature.as_ref());
            if equal {
                (200, duration)
            } else {
                (500, duration)
            }
        }
    }

    fn attack<const N: usize>(chall: &Challenge, data: &[u8]) -> Sha1Digest {
        let mut recovered = AlignedBytes([0u8; 20]);

        for i in 0..recovered.0.len() {
            recovered.0[i] = (u8::MIN..=u8::MAX)
                .max_by_key(|&guess| {
                    recovered.0[i] = guess;

                    // Collect N runs and see how well they correlate with the increased duration
                    let total_time = (0..N)
                        .map(|_| chall.challenge(data, Sha1Digest::from(recovered)).1)
                        .sum::<Duration>();

                    total_time / N as u32
                })
                .expect("Max on non-empty iterator always returns a value");
        }

        Sha1Digest::from(recovered)
    }

    #[test]
    fn challenge32() {
        let chall = Challenge::new();
        let data = b"My name is jeff and I can count to 1 milllion!!!";
        let sig = attack::<10>(&chall, data);
        assert_eq!(chall.challenge(data, sig).0, 200);
    }
}
