mod chall25 {
    use anyhow::Result;
    use rusty_pals::crypto::aes::{decrypt, encrypt, Aes128, Iv, Mode};
    use rusty_pals::rand::{Rng32, XorShift32};
    use rusty_pals::xor::{xor_blocks, xor_with_key};

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
            let ciphertext = encrypt(include_str!("files/7_correct.txt"), &key, nonce, Mode::CTR);

            Self {
                key,
                nonce,
                ciphertext,
            }
        }

        fn edit(&self, offset: usize, newtext: impl AsRef<[u8]>) -> Vec<u8> {
            let mut dec = decrypt(&self.ciphertext, &self.key, self.nonce, Mode::CTR);
            for (d, n) in dec.iter_mut().skip(offset).zip(newtext.as_ref().iter()) {
                *d = *n;
            }

            encrypt(dec, &self.key, self.nonce, Mode::CTR)
        }
    }

    #[test]
    fn challenge25() -> Result<()> {
        let chall = Challenge::new();
        let pt = attack(&chall)?;
        assert_eq!(pt, include_str!("files/7_correct.txt"));

        Ok(())
    }

    fn attack(chall: &Challenge) -> Result<String> {
        let ct = chall.ciphertext.clone();
        let key_xor_a = chall.edit(0, vec![b'A'; ct.len()]);
        let keystream = xor_with_key(key_xor_a, "A")?;
        Ok(String::from_utf8(xor_blocks(ct, keystream)?)?)
    }
}

mod chall26 {
    use anyhow::Result;
    use rusty_pals::crypto::aes::{decrypt, encrypt, Aes128, Mode};
    use rusty_pals::rand::{Rng32, XorShift32};
    use rusty_pals::util::cast_as_array;
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
            enc.extend_from_slice(&encrypt(s, &self.key, nonce, Mode::CTR));
            enc
        }

        fn decrypt(&self, data: impl AsRef<[u8]>) -> bool {
            let data = data.as_ref();
            let (nonce_bytes, data) = data.split_at(mem::size_of::<u64>());
            let nonce = u64::from_be_bytes(*cast_as_array(nonce_bytes));
            let dec = decrypt(data, &self.key, nonce, Mode::CTR);
            let text = String::from_utf8_lossy(&dec);

            let needle = ";admin=true;";
            text.contains(needle)
        }
    }

    #[test]
    fn challenge26() -> Result<()> {
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
    use anyhow::Result;
    use rusty_pals::crypto::{
        aes::{decrypt, encrypt, Aes, Aes128, Mode},
        pad,
    };
    use rusty_pals::rand::{Rng32, XorShift32};
    use rusty_pals::util::cast_as_arrays;
    use rusty_pals::xor::xor_block_simd;
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
            encrypt(s, &self.key, self.iv, Mode::CBC)
        }

        fn decrypt(&self, data: impl AsRef<[u8]>) -> Result<bool, Vec<u8>> {
            let data = data.as_ref();
            let dec = decrypt(data, &self.key, self.iv, Mode::CBC);
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
    use rusty_pals::crypto::{sha1::Sha1, Hasher};
    use rusty_pals::rand::{Rng32, XorShift32};

    pub(super) type Digest = <Sha1 as Hasher>::Digest;
    pub(super) struct Challenge {
        key: [u8; 20],
    }

    impl Challenge {
        pub(super) fn new() -> Self {
            Self {
                key: XorShift32::new().gen_array(),
            }
        }

        pub(super) fn mac(&self, message: impl AsRef<[u8]>) -> Digest {
            let mut hasher = Sha1::new();
            hasher.update(self.key);
            hasher.update(message.as_ref());
            hasher.finalize();
            hasher.digest()
        }

        pub(super) fn is_message_valid(&self, message: impl AsRef<[u8]>, mac: Digest) -> bool {
            self.mac(message) == mac
        }
    }

    #[test]
    fn challenge28() {
        let chall = Challenge::new();
        let mut data = b"I should probably write some cool movie quote here for some future dev to find and smile at, but alas I can't be arsed.".to_vec();
        let mac = chall.mac(&data);
        assert!(chall.is_message_valid(&data, mac));
        data[5] = b'1';
        assert!(!chall.is_message_valid(&data, mac));
        assert!(!chall.is_message_valid(&data, [1, 2, 3, 4, 5].into()));
    }
}

mod chall29 {
    use super::chall28::{Challenge, Digest};
    use rusty_pals::crypto::{sha1::Sha1, Hasher};

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
        let chall = Challenge::new();
        let data = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let mac = chall.mac(&data);
        let (new_data, new_mac) = attack(data, mac);
        assert!(new_data.ends_with(b";admin=true"));
        assert!(chall.is_message_valid(new_data, new_mac));
    }
}
