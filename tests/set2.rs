use color_eyre::eyre::Result;
use rusty_pals::encoding::Decodable;
use rusty_pals::encryption::aes::{decrypt, Aes128, Mode};
use rusty_pals::encryption::pad;

#[test]
fn challenge9() -> Result<()> {
    let input = "YELLOW SUBMARINE";
    let padded = pad::pkcs7(input, 20);
    assert_eq!(padded, b"YELLOW SUBMARINE\x04\x04\x04\x04");

    Ok(())
}

#[test]
fn challenge10() -> Result<()> {
    let mut input = include_str!("files/10.txt").to_string();
    input.retain(|c| c != '\n');
    let data = input.decode_b64()?;
    let key = Aes128::new(b"YELLOW SUBMARINE");
    let iv = [0u8; 16];
    let mut dec = decrypt(&data, &key, Some(&iv), Mode::CBC);
    pad::pkcs7_unpad_owned(&mut dec)?;
    assert_eq!(dec, include_bytes!("files/10_correct.txt"));

    Ok(())
}

#[cfg(test)]
mod chal11 {
    use color_eyre::Result;
    use rusty_pals::encryption::{
        aes::{encrypt, Aes, Aes128, Mode},
        pad,
    };
    use rusty_pals::rand::XorShift32;
    use rusty_pals::util::{self, cast_as_arrays};

    fn encryption_oracle(rng: &mut XorShift32, input: impl AsRef<[u8]>) -> Result<(bool, Vec<u8>)> {
        let n_before = 5 + (rng.gen() % 5) as usize;
        let n_after = 5 + (rng.gen() % 5) as usize;
        let mut data = rng.gen_bytes(n_before);
        data.extend_from_slice(input.as_ref());
        data.extend_from_slice(&rng.gen_bytes(n_after));
        pad::pkcs7_into(&mut data, Aes128::BLOCK_SIZE as u8);

        let key = Aes128::new(&rng.gen_array());
        let gen_ecb = rng.gen_bool();
        let enc = if gen_ecb {
            encrypt(&data, &key, None, Mode::ECB)
        } else {
            let iv = rng.gen_array();
            encrypt(&data, &key, Some(&iv), Mode::CBC)
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
    fn challenge11() -> Result<()> {
        let mut count_correct = 0;
        let num_rounds = 10000;
        let mut rng = XorShift32::new(42)?;
        for _ in 0..num_rounds {
            let (is_ecb, encrypted) = encryption_oracle(&mut rng, "a".repeat(43))?;
            let is_ecb_guess = detect_mode(encrypted);
            count_correct += (is_ecb == is_ecb_guess) as usize;
        }

        assert_eq!(count_correct, num_rounds);

        Ok(())
    }
}

#[cfg(test)]
mod chal12 {
    use color_eyre::eyre::{ensure, eyre, Result};
    use rusty_pals::encoding::Decodable;
    use rusty_pals::encryption::aes::{encrypt, Aes, Aes128, Mode};
    use rusty_pals::encryption::oracle::EncryptionOracle;
    use rusty_pals::encryption::pad;
    use rusty_pals::rand::XorShift32;
    use rusty_pals::util::{cast_as_array, cast_as_arrays};
    use std::collections::{HashMap, HashSet, VecDeque};

    #[test]
    fn challenge12() -> Result<()> {
        let mut rng = XorShift32::new(42)?;
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

    fn attack(oracle: impl EncryptionOracle) -> Result<Vec<u8>> {
        const BLKSZ: usize = Aes128::BLOCK_SIZE;

        // Step 1. find the block size
        // we can feeding the cipher longer and longer strings until the length
        // of the returned ciphertext is becomes longer
        let empty_len = oracle.encrypt("").len();
        let mut i = 1;
        let block_size = loop {
            let l = oracle.encrypt("a".repeat(i)).len();
            if l != empty_len {
                break l - empty_len;
            }
            i += 1;
        };
        assert_eq!(block_size, BLKSZ);

        // Step 2: Detect the cipher mode
        // out input is of the form user-string || secret, so we can provide a string of 2*block_size
        // bytes to get two identical blocks at the beginning
        let enc = oracle.encrypt("a".repeat(2 * block_size));
        ensure!(
            &enc[0..BLKSZ] == &enc[BLKSZ..2 * BLKSZ],
            "Oracle is not using the ECB encryption mode."
        );

        // Step 3/4: craft the block mappings
        let mut prefix_mapper = PrefixMapper::<BLKSZ>::new();
        let mut prefix = VecDeque::from(vec![b'A'; block_size]);
        prefix_mapper.compute_mappings(cast_as_array(prefix.make_contiguous()), &oracle)?;

        // Step 5: Match the output of the one-byte-short input
        let enc = oracle.encrypt(&prefix.as_slices().0[..BLKSZ - 1]);
        let block = &enc[..block_size];
        let decoded = prefix_mapper
            .get(block)
            .ok_or_else(|| eyre!("Failed to recover byte from secret."))?;

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
        fn new(rng: &mut XorShift32) -> Result<Self> {
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
            encrypt(data, &self.key, None, Mode::ECB)
        }
    }

    /// A struct storing the mappings for all the prefixes, ensuring they are only calculated once
    #[derive(Default, Debug, Clone)]
    struct PrefixMapper<const BLKSZ: usize> {
        mapping: HashMap<[u8; BLKSZ], u8>,
        prefixes: HashSet<[u8; BLKSZ]>,
    }

    impl<const BLKSZ: usize> PrefixMapper<BLKSZ> {
        fn new() -> Self {
            Default::default()
        }

        /// Compute the mappings for a given prefix
        fn compute_mappings(
            &mut self,
            prefix: &[u8; BLKSZ],
            oracle: &impl EncryptionOracle,
        ) -> Result<()> {
            let mut block = *prefix;
            // ignore the last byte of the prefix
            block[BLKSZ - 1] = 0;

            // check wether we have already calculated these prefixes
            if !self.prefixes.insert(block) {
                return Ok(());
            }

            for b in u8::MIN..=u8::MAX {
                block[BLKSZ - 1] = b;
                let mut enc = oracle.encrypt(&block);
                enc.truncate(BLKSZ);
                let block: &[u8; BLKSZ] = cast_as_array(&enc[..]);
                self.mapping.insert(*block, b);
            }

            Ok(())
        }

        /// Get elements from the mapping
        fn get(&self, block: &[u8]) -> Option<u8> {
            self.mapping.get(block).copied()
        }
    }
}
