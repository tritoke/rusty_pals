use crypto_core::crypto::aes::{decrypt, Aes128, Mode};
use crypto_core::encoding::{Decodable, DecodingError};
use crypto_core::rand::{Mt19937, Rng32};
use crypto_core::util::CastError;
use crypto_core::xor::XorError;
use std::str::Utf8Error;
use std::time::SystemTimeError;

mod helpers;
use helpers::*;

#[derive(Debug, Clone)]
pub enum ChallengeError {
    DecodingError(DecodingError),
    XorError(XorError),
    Utf8Error(Utf8Error),
    SystemTimeError(SystemTimeError),
    CastError(CastError),
}

impl_error_boilerplate!(ChallengeError);
impl_error_from_types!(ChallengeError: DecodingError, XorError, Utf8Error, SystemTimeError, CastError);

pub type ChallengeResult<T> = Result<T, ChallengeError>;

mod chal17 {
    use crypto_core::crypto::{
        aes::{decrypt, encrypt, Aes, Aes128, Mode},
        pad,
    };
    use crypto_core::rand::{Rng32, XorShift32};
    use crypto_core::util::cast_as_array;

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
            out.extend_from_slice(&encrypt(&data, self.key, iv, Mode::CBC));
            out
        }

        fn is_padding_valid(&self, ct: &[u8]) -> bool {
            let (iv, ct) = ct.split_at(Aes128::BLOCK_SIZE);
            let mut dec = decrypt(ct, self.key, *cast_as_array(iv), Mode::CBC);
            pad::pkcs7_unpad_owned(&mut dec).is_ok()
        }
    }

    #[test]
    fn challenge17() {
        let mut rng = XorShift32::new();

        let mut chall = Challenge::new(&mut rng);
        let (ct, pt) = attack(&mut chall);

        let (iv, ct) = ct.split_at(Aes128::BLOCK_SIZE);
        let mut pt_correct = decrypt(ct, chall.key, *cast_as_array(iv), Mode::CBC);
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
            let plain = break_final_block(chall, &ct[..blocks * Aes128::BLOCK_SIZE]);
            pt.extend_from_slice(&plain);
        }

        pad::pkcs7_unpad_owned(&mut pt)
            .expect("Failed to recover message - plaintext has invalid padding.");

        (ct, pt)
    }
}

#[test]
fn challenge18() -> ChallengeResult<()> {
    let enc =
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".decode_b64()?;

    let key = Aes128::new(b"YELLOW SUBMARINE");
    let dec = decrypt(&enc, key, 0, Mode::CTR);

    assert_eq!(dec.len(), enc.len());
    assert_eq!(dec, b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");

    Ok(())
}

#[allow(unused, unreachable_code)]
mod chall19 {
    use crate::ChallengeResult;
    use crypto_core::crypto::aes::{encrypt, Aes128, Iv, Mode};
    use crypto_core::encoding::{Decodable, DecodingError, Encodable};
    use crypto_core::rand::{Rng32, XorShift32};
    use crypto_core::xor::xor_blocks;

    // I don't like this challenge, it makes me sad
    // #[test]
    fn challenge19() -> ChallengeResult<()> {
        let key = Aes128::new(&XorShift32::new().gen_array());

        let true_pts: Vec<Vec<u8>> = include_str!("files/19.txt")
            .lines()
            .map(|line| line.decode_b64())
            .collect::<Result<_, _>>()?;

        // generate the ciphertexts
        let cts: Vec<Vec<u8>> = true_pts
            .iter()
            .map(|pt| Ok(encrypt(pt, key, Iv::Nonce(0), Mode::CTR)))
            .collect::<ChallengeResult<_>>()?;

        let ct_refs: Vec<&[u8]> = cts.iter().map(AsRef::as_ref).collect();
        let pts = attack(ct_refs.as_ref())?;

        assert_eq!(pts, true_pts);

        Ok(())
    }

    fn attack(cts: &[&[u8]]) -> ChallengeResult<Vec<Vec<u8>>> {
        for (&ct1, &ct2) in cts.iter().zip(cts.iter().skip(1)) {
            let cl = usize::min(ct1.len(), ct2.len());
            let xorred = xor_blocks(&ct1[..cl], &ct2[..cl])?;
            xorred.encode_hex();
        }
        todo!("fuck this")
    }
}

mod chall20 {
    use crate::ChallengeResult;
    use crypto_core::crypto::aes::{encrypt, Aes128, Iv, Mode};
    use crypto_core::encoding::Decodable;
    use crypto_core::rand::{Rng32, XorShift32};
    use crypto_core::xor::{break_repeating_key_xor, xor_blocks};

    #[test]
    fn challenge20() -> ChallengeResult<()> {
        let key = Aes128::new(&XorShift32::new().gen_array());

        let true_pts: Vec<Vec<u8>> = include_str!("files/19.txt")
            .lines()
            .map(|line| line.decode_b64())
            .collect::<Result<_, _>>()?;

        // generate the ciphertexts
        let cts: Vec<Vec<u8>> = true_pts
            .iter()
            .map(|pt| Ok(encrypt(pt, key, Iv::Nonce(0), Mode::CTR)))
            .collect::<ChallengeResult<_>>()?;

        let ct_refs: Vec<&[u8]> = cts.iter().map(AsRef::as_ref).collect();
        let pts = attack(ct_refs.as_ref())?;

        for (pt, mut true_pt) in pts.into_iter().zip(true_pts.into_iter()) {
            // assert the pts are correct up to their length
            true_pt.truncate(pt.len());
            let pt = std::str::from_utf8(&pt)?;
            let true_pt = std::str::from_utf8(&true_pt)?;
            assert!(pt.eq_ignore_ascii_case(true_pt));
        }

        Ok(())
    }

    fn attack(cts: &[&[u8]]) -> ChallengeResult<Vec<Vec<u8>>> {
        let common_length = cts
            .iter()
            .map(|x| x.len())
            .min()
            .expect("Found no ciphertexts");

        let concat_cts: Vec<u8> = cts
            .iter()
            .flat_map(|x| &x[..common_length])
            .copied()
            .collect();
        let key = break_repeating_key_xor(concat_cts, common_length..=common_length, 4)?;

        cts.iter()
            .map(|ct| xor_blocks(&ct[..common_length], &key))
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

#[test]
fn challenge21() {
    let mut rng: Mt19937 = Default::default();
    assert_eq!(rng.gen(), 3499211612);
    assert_eq!(rng.gen(), 581869302);
    assert_eq!(rng.gen(), 3890346734);
    assert_eq!(rng.gen(), 3586334585);
    assert_eq!(rng.gen(), 545404204);
    assert_eq!(rng.gen(), 4161255391);
    assert_eq!(rng.gen(), 3922919429);
    assert_eq!(rng.gen(), 949333985);
}

mod chall22 {
    use crypto_core::rand::{Mt19937, Rng32};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::ChallengeResult;

    #[test]
    fn challenge22() -> ChallengeResult<()> {
        let mut rng = Mt19937::new();
        let mut unix_ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        unix_ts += 40 + (rng.gen() % (1000 - 40));
        let seed = unix_ts;
        rng.seed(seed);
        let n = rng.gen();
        unix_ts += 500 + (rng.gen() % 1000);
        assert_eq!(crack(n, unix_ts), seed);
        Ok(())
    }

    fn crack(n: u32, curr_unix_ts: u32) -> u32 {
        let mut ts = curr_unix_ts;
        let mut rng = Mt19937::new();
        loop {
            rng.seed(ts);
            if rng.gen() == n {
                break ts;
            }
            ts -= 1;
        }
    }
}

mod chall23 {
    use crypto_core::rand::{Mt19937, Rng32};
    use crypto_core::util::{try_cast_as_array, CastResult};
    use std::iter;

    use crate::ChallengeResult;

    fn untemper(mut t: u32) -> u32 {
        use crypto_core::rand::mt19937::constants::*;

        fn bit(x: u32, n: u32) -> u32 {
            x & (1 << n)
        }

        fn inv_rshift(x: u32, shift: u32, mask: Option<u32>) -> u32 {
            let mask = mask.unwrap_or(u32::MAX);
            let mut res = 0;
            for i in 0..W {
                if i < shift {
                    res |= bit(x, W - 1 - i);
                } else {
                    res |= bit(x, W - 1 - i)
                        ^ (bit(mask, W - i - 1) != 0)
                            .then(|| bit(res, W - 1 - i + shift) >> shift)
                            .unwrap_or(0);
                }
            }
            res
        }

        fn inv_lshift(x: u32, shift: u32, mask: Option<u32>) -> u32 {
            let mask = mask.unwrap_or(u32::MAX);
            let mut res = 0;
            for i in 0..W {
                if i < shift {
                    res |= bit(x, i);
                } else {
                    res |= bit(x, i)
                        ^ (bit(mask, i) != 0)
                            .then(|| bit(res, i - shift) << shift)
                            .unwrap_or(0);
                }
            }
            res
        }

        t = inv_rshift(t, L, None);
        t = inv_lshift(t, T, Some(C));
        t = inv_lshift(t, S, Some(B));
        inv_rshift(t, U, Some(D))
    }

    #[test]
    fn test_untemper() {
        assert_eq!(untemper(Mt19937::temper(0xDEADBEEF)), 0xDEADBEEF);
        assert_eq!(untemper(Mt19937::temper(0xC0FFEE)), 0xC0FFEE);
        assert_eq!(untemper(Mt19937::temper(u32::MAX)), u32::MAX);
        assert_eq!(untemper(Mt19937::temper(u32::MIN)), u32::MIN);
    }

    #[test]
    fn challenge23() -> ChallengeResult<()> {
        let mut rng = Mt19937::new();
        let tapped: Vec<_> = iter::from_fn(|| Some(rng.gen())).take(624).collect();
        let mut cloned = attack(&tapped[..])?;

        for _ in 0..1000 {
            assert_eq!(rng.gen(), cloned.gen());
        }

        Ok(())
    }

    fn attack(outputs: &[u32]) -> CastResult<Mt19937> {
        let raw_state: Vec<u32> = outputs.iter().copied().map(untemper).collect();
        Ok(Mt19937::from_state(try_cast_as_array(&raw_state[..])?))
    }
}

mod chall24 {
    use crypto_core::encoding::Encodable;
    use crypto_core::rand::{Mt19937, Rng32, XorShift32};
    use crypto_core::util::{as_chunks, as_chunks_mut};
    use crypto_core::xor::xor_block_simd_into;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::ChallengeResult;

    fn encrypt(data: impl AsRef<[u8]>, seed: u16) -> Vec<u8> {
        let mut data = data.as_ref().to_vec();
        let mut rng = Mt19937::new();
        rng.seed(seed as u32);
        let keystream = rng.gen_bytes(data.len());

        let (data_chunks, data_rmdr) = as_chunks_mut(&mut data);
        let (key_chunks, key_rmdr) = as_chunks(&keystream);

        // SIMD for speed I guess lol, might as well use all these functions I've written
        for (dc, kc) in data_chunks.iter_mut().zip(key_chunks.iter()) {
            xor_block_simd_into(kc, dc);
        }
        for (d, k) in data_rmdr.iter_mut().zip(key_rmdr.iter()) {
            *d ^= k;
        }

        data
    }

    #[test]
    fn test_m19937_stream_cipher() {
        let data =
            "Wow this is a really long string, some actual SIMD stuff might get used for this lmao";

        let seed = 0x1337;
        let enc_data = encrypt(data, seed);
        assert_eq!(encrypt(enc_data, seed), data.as_bytes());
    }

    fn get_rand_ciphertext() -> (u16, Vec<u8>) {
        let mut rng = XorShift32::new();
        let rand_chars = (rng.gen() % 40) + 10;
        let mut ciphertext = rng.gen_bytes(rand_chars as usize);
        ciphertext.extend_from_slice(&[b'A'; 14][..]);
        let seed = rng.gen() as u16;
        (seed, encrypt(ciphertext, seed))
    }

    #[test]
    fn challenge24() -> ChallengeResult<()> {
        let (seed, ct) = get_rand_ciphertext();
        assert_eq!(recover_seed(&ct[..]), seed);

        let curr_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        let valid_token = create_recovery_token(curr_time);

        assert!(token_created_in_last_five_minutes(valid_token)?);

        // create a token 500 seconds in the past
        let invalid_token = create_recovery_token(curr_time - 500);
        assert!(!token_created_in_last_five_minutes(invalid_token)?);

        Ok(())
    }

    fn recover_seed(ct: &[u8]) -> u16 {
        let known = [b'A'; 14];
        for seed in u16::MIN..=u16::MAX {
            let enc = encrypt(ct, seed);
            if enc.ends_with(&known[..]) {
                return seed;
            }
        }

        unreachable!("The encrypted data was seeded with a 16 bit value, we will find it :)");
    }

    fn create_recovery_token(time: u32) -> String {
        let mut rng = Mt19937::new();
        rng.seed(time);
        rng.gen_bytes(20).encode_b64()
    }

    fn token_created_in_last_five_minutes(token: String) -> ChallengeResult<bool> {
        let curr_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        for s in 0..=360 {
            if create_recovery_token(curr_time - s) == token {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
