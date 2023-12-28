#![allow(non_snake_case)]

use rusty_pals::bignum::nist_consts::{NIST_G, NIST_P};
use rusty_pals::bignum::Bignum;
use rusty_pals::rand::{Rng32, XorShift32};
// a bigint type big enough to handle modexp for NIST's p value
type Bigint = Bignum<48>;

#[test]
fn challenge33_small() {
    let mut rng = XorShift32::new();

    let p = 37;
    let g = 5;

    let a = rng.gen() % p;
    let b = rng.gen() % p;

    // bootleg modexp
    fn modexp(x: u32, e: u32, p: u32) -> u32 {
        let mut X = x;
        for _ in 0..e {
            X = X * x % p;
        }
        X
    }

    let A = modexp(g, a, p);
    let B = modexp(g, b, p);

    let s_a = modexp(A, b, p);
    let s_b = modexp(B, a, p);

    assert_eq!(s_a, s_b);
}

#[test]
fn challenge33_big() {
    let mut rng = XorShift32::new();

    let a = Bigint::random(&mut rng) % NIST_P;
    let b = Bigint::random(&mut rng) % NIST_P;
    let A = NIST_G.modexp(a, NIST_P);
    let B = NIST_G.modexp(b, NIST_P);

    let K_a = B.modexp(a, NIST_P);
    let K_b = A.modexp(b, NIST_P);

    assert_eq!(K_a, K_b);
}

mod chall24 {
    // use std::sync::mpsc;

    use rusty_pals::{
        crypto::{
            aes::{self, Aes, Aes128, Iv},
            pad::{pkcs7, pkcs7_unpad_owned},
            sha1::Sha1,
            Hasher,
        },
        util::cast_as_array,
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct Initial {
        pub_key: Bigint,
        generator: Bigint,
        modulus: Bigint,
    }

    #[derive(Debug, Clone)]
    struct ResponsePublicKey {
        key: Bigint,
    }

    #[derive(Debug, Clone)]
    struct EncMessage {
        iv: Iv,
        message: Vec<u8>,
    }

    trait Party {
        fn new(rng: impl Rng32) -> Self;

        fn init(&mut self) -> Initial;
        fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey;
        fn recv_pub(&mut self, resp_pub: ResponsePublicKey);

        fn enc(&self, msg: &[u8]) -> EncMessage;
        fn dec(&self, enc_msg: EncMessage) -> Vec<u8>;
    }

    struct Honest {
        priv_key: Bigint,
        shared_secret: Option<Aes128>,
    }

    fn compute_enc_key(shared_key: Bigint) -> Aes128 {
        eprintln!("[compute_enc_key] shared_key={shared_key}");

        let mut hasher = Sha1::new();
        hasher.update(shared_key);
        hasher.finalize();
        let digest = hasher.digest();
        Aes128::new(cast_as_array(&digest.as_ref()[..16]))
    }

    impl Party for Honest {
        fn new(rng: impl Rng32) -> Self {
            let priv_key = Bigint::random(rng);

            Self {
                priv_key,
                shared_secret: None,
            }
        }

        fn init(&mut self) -> Initial {
            Initial {
                generator: NIST_G,
                modulus: NIST_P,
                pub_key: NIST_G.modexp(self.priv_key, NIST_P),
            }
        }

        fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey {
            let pub_key = init.generator.modexp(self.priv_key, init.modulus);
            let shared_key = init.pub_key.modexp(self.priv_key, init.modulus);
            eprintln!("shared_key={shared_key}");

            self.shared_secret = Some(compute_enc_key(shared_key));

            ResponsePublicKey { key: pub_key }
        }

        fn recv_pub(&mut self, resp_pub: ResponsePublicKey) {
            let shared_key = resp_pub.key.modexp(self.priv_key, NIST_P);
            eprintln!("shared_key={shared_key}");

            self.shared_secret = Some(compute_enc_key(shared_key));
        }

        fn enc(&self, msg: &[u8]) -> EncMessage {
            let mut rng = XorShift32::new();

            let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
            let iv = Iv::Block(rng.gen_array());
            let enc = aes::encrypt(padded, self.shared_secret.unwrap(), iv, aes::Mode::CBC);

            EncMessage { iv, message: enc }
        }

        fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
            let EncMessage { iv, message: enc } = enc_msg;

            let mut dec = aes::decrypt(enc, self.shared_secret.unwrap(), iv, aes::Mode::CBC);
            pkcs7_unpad_owned(&mut dec).unwrap();
            dec
        }
    }

    struct Malicious {
        key: Aes128,
    }

    impl Party for Malicious {
        fn new(_rng: impl Rng32) -> Self {
            Self {
                key: compute_enc_key(Bigint::ZERO),
            }
        }

        fn init(&mut self) -> Initial {
            Initial {
                pub_key: NIST_P,
                generator: NIST_G,
                modulus: NIST_P,
            }
        }

        fn resp_pub(&mut self, _init: Initial) -> ResponsePublicKey {
            ResponsePublicKey { key: NIST_P }
        }

        fn recv_pub(&mut self, _resp: ResponsePublicKey) {}

        fn enc(&self, msg: &[u8]) -> EncMessage {
            let mut rng = XorShift32::new();

            let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
            let iv = Iv::Block(rng.gen_array());
            let enc = aes::encrypt(padded, self.key, iv, aes::Mode::CBC);

            EncMessage { iv, message: enc }
        }

        fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
            let EncMessage { iv, message: enc } = enc_msg;

            let mut dec = aes::decrypt(enc, self.key, iv, aes::Mode::CBC);
            pkcs7_unpad_owned(&mut dec).unwrap();
            dec
        }
    }

    fn diffie_hellman<A: Party, B: Party>(msg: &[u8], mut rng: impl Rng32) {
        let mut a = A::new(&mut rng);
        let mut b = B::new(&mut rng);

        let init = a.init();
        let resp = b.resp_pub(init);
        a.recv_pub(resp);

        let a_to_a = a.dec(a.enc(msg));
        let a_to_b = a.dec(b.enc(msg));
        let b_to_a = b.dec(a.enc(msg));
        let b_to_b = b.dec(b.enc(msg));

        assert_eq!(a_to_a, msg);
        assert_eq!(a_to_b, msg);
        assert_eq!(b_to_a, msg);
        assert_eq!(b_to_b, msg);
    }

    fn mitm<A: Party, B: Party, M: Party>(msg: &[u8], mut rng: impl Rng32) {
        let mut a = A::new(&mut rng);
        let mut b = B::new(&mut rng);
        let mut m = M::new(&mut rng);

        eprintln!("a_init");
        let a_init = a.init();
        eprintln!("m_init");
        let m_init = m.init();

        eprintln!("m_resp");
        let m_resp = m.resp_pub(a_init);
        eprintln!("a.recv_pub");
        a.recv_pub(m_resp);

        eprintln!("b.resp_pub");
        let b_resp = b.resp_pub(m_init);
        eprintln!("m.recv_pub");
        m.recv_pub(b_resp);

        let a_enc = a.enc(msg);
        let m_dec = m.dec(a_enc.clone());
        let b_dec = b.dec(a_enc);

        assert_eq!(m_dec, msg);
        assert_eq!(b_dec, msg);
    }

    #[test]
    fn challenge34() {
        let mut rng = XorShift32::new();

        diffie_hellman::<Honest, Honest>(b"My name is jeff and I love to eat socks", &mut rng);
        mitm::<Honest, Honest, Malicious>(b"My name is socks and I love to eat jeff", &mut rng);
    }
}
