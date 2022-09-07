mod chal17 {
    use rusty_pals::encoding::Encodable;
    use rusty_pals::encryption::{
        aes::{decrypt, encrypt, Aes, Aes128, Mode},
        pad,
    };
    use rusty_pals::rand::XorShift32;
    use rusty_pals::util::cast_as_array;

    struct Challenge<'a> {
        key: Aes128,
        pts: Vec<String>,
        rng: &'a mut XorShift32,
    }

    impl<'a> Challenge<'a> {
        fn new(rng: &'a mut XorShift32) -> Self {
            Self {
                key: Aes128::new(&rng.gen_array()),
                pts: include_str!("files/17.txt")
                    .lines()
                    .map(str::to_string)
                    .collect(),
                rng,
            }
        }

        fn gen_ct(&mut self) -> Vec<u8> {
            // select a string at random
            let pt = self.pts[self.rng.gen() as usize % self.pts.len()].clone();
            let mut data = pt.into_bytes();
            pad::pkcs7_into(&mut data, Aes128::BLOCK_SIZE as u8);
            let iv = self.rng.gen_array();
            let mut out = iv.to_vec();
            out.extend_from_slice(&encrypt(&data, &self.key, Some(&iv), Mode::CBC));
            out
        }

        fn is_padding_valid(&self, ct: &[u8]) -> bool {
            let (iv, ct) = ct.split_at(Aes128::BLOCK_SIZE);
            let mut dec = decrypt(ct, &self.key, Some(cast_as_array(iv)), Mode::CBC);
            pad::pkcs7_unpad_owned(&mut dec).is_ok()
        }
    }

    #[test]
    fn challenge17() {
        let mut rng = XorShift32::new(1234);

        let mut chall = Challenge::new(&mut rng);
        let (ct, pt) = attack(&mut chall);

        let (iv, ct) = ct.split_at(Aes128::BLOCK_SIZE);
        let mut pt_correct = decrypt(ct, &chall.key, Some(cast_as_array(iv)), Mode::CBC);
        pad::pkcs7_unpad_owned(&mut pt_correct).unwrap();
        assert_eq!(pt, pt_correct);
    }

    fn break_final_block(chall: &Challenge<'_>, ct: &[u8]) -> [u8; Aes128::BLOCK_SIZE] {
        // at least two blocks are needed
        assert!(ct.len() >= Aes128::BLOCK_SIZE * 2);

        const BS: usize = Aes128::BLOCK_SIZE;
        let mut pt = [0u8; Aes128::BLOCK_SIZE];
        let mut ct = ct.to_vec();

        let cl = ct.len();
        'outer: for b1 in u8::MIN..=u8::MAX {
            ct[cl - 1 - BS] ^= b1;
            if chall.is_padding_valid(&ct) {
                // the only value in [0..255] that is equal to 2 after this XOR is 1
                // this means that if we can get valid padding with a second byte
                // that we have the actual last two bytes in this chunk
                ct[cl - 1 - BS] ^= 1 ^ 2;
                for b2 in u8::MIN..=u8::MAX {
                    ct[cl - 2 - BS] ^= b2;
                    if chall.is_padding_valid(&ct) {
                        pt[BS - 1] = b1 ^ 1;
                        pt[BS - 2] = b2 ^ 2;

                        // undo XORs
                        ct[cl - 2 - BS] ^= b2;
                        ct[cl - 1 - BS] ^= b1 ^ 1 ^ 2;
                        break 'outer;
                    }
                    ct[cl - 2 - BS] ^= b2;
                }
                ct[cl - 1 - BS] ^= 1 ^ 2;
            }
            ct[cl - 1 - BS] ^= b1;
        }

        // bruteforce the remaining bytes
        for i in 3..=BS {
            // apply initial XORs
            for j in 1..i {
                ct[cl - BS - j] ^= pt[BS - j] ^ i as u8;
            }

            for b in u8::MIN..u8::MAX {
                ct[cl - BS - i] ^= b;
                if chall.is_padding_valid(&ct) {
                    pt[BS - i] = b ^ i as u8;

                    // undo xor so we can break
                    ct[cl - BS - i] ^= b;
                    break;
                }
                ct[cl - BS - i] ^= b;
            }

            // undo initial XORs
            for j in 1..i {
                ct[cl - BS - j] ^= pt[BS - j] ^ i as u8;
            }
        }

        pt
    }

    fn attack(chall: &mut Challenge<'_>) -> (Vec<u8>, Vec<u8>) {
        let ct = chall.gen_ct();

        let mut pt = vec![];
        for blocks in 2..=ct.len() / Aes128::BLOCK_SIZE {
            let plain = break_final_block(&chall, &ct[..blocks * Aes128::BLOCK_SIZE]);
            pt.extend_from_slice(&plain);
        }

        pad::pkcs7_unpad_owned(&mut pt)
            .expect("Failed to recover message - plaintext has invalid padding.");

        (ct, pt)
    }
}

panic!();
