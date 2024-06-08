#![allow(non_snake_case)]

use std::rc::Rc;

use crypto_core::bignum::nist::{NIST_G, NIST_P};
use crypto_core::bignum::{Bignum, MontyForm, MontyInfo};
use crypto_core::crypto::aes::Aes128;
use crypto_core::crypto::sha1::Sha1;
use crypto_core::crypto::Hasher as _;
use crypto_core::rand::{Rng32, XorShift32};
use crypto_core::util::cast_as_array;

type U1536 = Bignum<24>;
type Context = Rc<MontyInfo<24>>;
type M1536 = MontyForm<24>;

#[derive(Debug, Clone)]
struct Group {
    generator: M1536,
    context: Context,
}

impl Group {
    fn gen_keypair(&self, rng: impl Rng32) -> (U1536, M1536) {
        let a = U1536::random(rng);
        let A = self.generator.pow(&a);
        (a, A)
    }
}

impl Default for Group {
    fn default() -> Self {
        let context = Rc::new(MontyInfo::new(NIST_P));
        let generator = M1536::new(&NIST_G, context.clone());
        Self { generator, context }
    }
}

fn compute_enc_key(shared_key: U1536) -> Aes128 {
    let mut hasher = Sha1::new();
    hasher.update(shared_key);
    hasher.finalize();
    let digest = hasher.digest();
    Aes128::new(cast_as_array(&digest.as_ref()[..16]))
}

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
    let group = Group::default();

    let (a, A) = group.gen_keypair(&mut rng);
    let (b, B) = group.gen_keypair(&mut rng);

    let K_a = B.pow(&a);
    let K_b = A.pow(&b);

    assert_eq!(K_a, K_b);
}

mod chall34 {
    use crypto_core::crypto::{
        aes::{self, Aes, Iv},
        pad::{pkcs7, pkcs7_unpad_owned},
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct Initial {
        pub_key: M1536,
        group: Group,
    }

    #[derive(Debug, Clone)]
    struct ResponsePublicKey {
        key: M1536,
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
        priv_key: U1536,
        shared_secret: Option<Aes128>,
    }

    impl Party for Honest {
        fn new(rng: impl Rng32) -> Self {
            let priv_key = U1536::random(rng);

            Self {
                priv_key,
                shared_secret: None,
            }
        }

        fn init(&mut self) -> Initial {
            let group = Group::default();
            Initial {
                pub_key: group.generator.pow(&self.priv_key),
                group,
            }
        }

        fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey {
            let pub_key = init.group.generator.pow(&self.priv_key);
            let shared_key = init.pub_key.pow(&self.priv_key);

            self.shared_secret = Some(compute_enc_key(shared_key.into()));

            ResponsePublicKey { key: pub_key }
        }

        fn recv_pub(&mut self, resp_pub: ResponsePublicKey) {
            let shared_key = resp_pub.key.pow(&self.priv_key);

            self.shared_secret = Some(compute_enc_key(shared_key.into()));
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
                key: compute_enc_key(U1536::ZERO),
            }
        }

        fn init(&mut self) -> Initial {
            let group = Group::default();
            Initial {
                pub_key: M1536::new(&Bignum::ZERO, group.context.clone()),
                group,
            }
        }

        fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey {
            ResponsePublicKey {
                key: M1536::new(&Bignum::ZERO, init.group.context),
            }
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

        let a_init = a.init();
        let m_init = m.init();

        let m_resp = m.resp_pub(a_init);
        a.recv_pub(m_resp);

        let b_resp = b.resp_pub(m_init);
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

// mod chall35 {
//     use crypto_core::{
//         crypto::{
//             aes::{self, Aes, Aes128, Iv},
//             pad::{pkcs7, pkcs7_unpad_owned},
//             sha1::Sha1,
//             Hasher,
//         },
//         util::cast_as_array,
//     };

//     use super::*;

//     #[derive(Debug, Clone)]
//     struct Initial {
//         generator: U1536,
//         modulus: U1536,
//     }

//     #[derive(Debug, Clone)]
//     struct Ack;

//     #[derive(Debug, Clone)]
//     struct ResponsePublicKey {
//         key: U1536,
//     }

//     #[derive(Debug, Clone)]
//     struct EncMessage {
//         iv: Iv,
//         message: Vec<u8>,
//     }

//     trait Party {
//         fn new(rng: impl Rng32) -> Self;

//         fn init(&mut self) -> Initial;
//         fn ack(&mut self, init: Initial) -> Ack;
//         fn send_pub(&mut self, ack: Ack) -> ResponsePublicKey;
//         fn reply_pub(&mut self, resp_pub: ResponsePublicKey) -> ResponsePublicKey;
//         fn recv_pub(&mut self, resp_pub: ResponsePublicKey);

//         fn enc(&self, msg: &[u8]) -> EncMessage;
//         fn dec(&self, enc_msg: EncMessage) -> Vec<u8>;
//     }

//     struct Honest {
//         priv_key: U1536,
//         generator: Option<M1536>,
//         context: Option<Context>,
//         shared_secret: Option<Aes128>,
//     }

//     fn compute_enc_key(shared_key: U1536) -> Aes128 {
//         let mut hasher = Sha1::new();
//         hasher.update(shared_key);
//         hasher.finalize();
//         let digest = hasher.digest();
//         Aes128::new(cast_as_array(&digest.as_ref()[..16]))
//     }

//     impl Party for Honest {
//         fn new(rng: impl Rng32) -> Self {
//             let priv_key = U1536::random(rng);

//             Self {
//                 priv_key,
//                 generator: None,
//                 context: None,
//                 shared_secret: None,
//             }
//         }

//         fn init(&mut self) -> Initial {
//             self.context = Some(Rc::new())
//             self.generator = Some(NIST_G);
//             self.modulus = Some(NIST_P);

//             Initial {
//                 generator: NIST_G,
//                 modulus: NIST_P,
//             }
//         }

//         fn ack(&mut self, init: Initial) -> Ack {
//             self.modulus = Some(init.modulus);
//             self.generator = Some(init.generator);

//             Ack
//         }

//         fn send_pub(&mut self, _ack: Ack) -> ResponsePublicKey {
//             let pub_key = self
//                 .generator
//                 .unwrap()
//                 .modexp(self.priv_key, self.modulus.unwrap());

//             ResponsePublicKey { key: pub_key }
//         }

//         fn reply_pub(&mut self, resp_pub: ResponsePublicKey) -> ResponsePublicKey {
//             let shared_key = resp_pub.key.modexp(self.priv_key, self.modulus.unwrap());
//             self.shared_secret = Some(compute_enc_key(shared_key));

//             let pub_key = self
//                 .generator
//                 .unwrap()
//                 .modexp(self.priv_key, self.modulus.unwrap());

//             ResponsePublicKey { key: pub_key }
//         }

//         fn recv_pub(&mut self, resp_pub: ResponsePublicKey) {
//             let shared_key = resp_pub.key.modexp(self.priv_key, self.modulus.unwrap());
//             self.shared_secret = Some(compute_enc_key(shared_key));
//         }

//         fn enc(&self, msg: &[u8]) -> EncMessage {
//             let mut rng = XorShift32::new();

//             let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
//             let iv = Iv::Block(rng.gen_array());
//             let enc = aes::encrypt(padded, self.shared_secret.unwrap(), iv, aes::Mode::CBC);

//             EncMessage { iv, message: enc }
//         }

//         fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
//             let EncMessage { iv, message: enc } = enc_msg;

//             let mut dec = aes::decrypt(enc, self.shared_secret.unwrap(), iv, aes::Mode::CBC);
//             pkcs7_unpad_owned(&mut dec).unwrap();
//             dec
//         }
//     }

//     // struct Malicious {
//     //     generator: U1536,
//     //     key: Aes128,
//     // }

//     // impl Party for Malicious {
//     //     fn new(generator: U1536) -> Self {
//     //         Self {
//     //             generator,
//     //             key: todo!(),
//     //         }
//     //     }

//     //     fn init(&mut self) -> Initial {
//     //         Initial {
//     //             generator: self.generator,
//     //             modulus: NIST_P,
//     //         }
//     //     }

//     //     fn ack(&mut self, init: Initial) -> Ack {
//     //         unimplemented!()
//     //     }

//     //     fn send_pub(&mut self, _ack: Ack) -> ResponsePublicKey {
//     //         let pub_key = self
//     //             .generator
//     //             .modexp(self.priv_key, self.modulus.unwrap());

//     //         ResponsePublicKey { key: pub_key }
//     //     }

//     //     fn reply_pub(&mut self, resp_pub: ResponsePublicKey) -> ResponsePublicKey {
//     //         let shared_key = resp_pub.key.modexp(self.priv_key, self.modulus.unwrap());
//     //         self.shared_secret = Some(compute_enc_key(shared_key));

//     //         let pub_key = self
//     //             .generator
//     //             .unwrap()
//     //             .modexp(self.priv_key, self.modulus.unwrap());

//     //         ResponsePublicKey { key: pub_key }
//     //     }

//     //     fn recv_pub(&mut self, resp_pub: ResponsePublicKey) {
//     //         let shared_key = resp_pub.key.modexp(self.priv_key, self.modulus.unwrap());
//     //         self.shared_secret = Some(compute_enc_key(shared_key));
//     //     }

//     //     fn enc(&self, msg: &[u8]) -> EncMessage {
//     //         let mut rng = XorShift32::new();

//     //         let padded = pkcs7(msg, Aes128::BLOCK_SIZE as u8);
//     //         let iv = Iv::Block(rng.gen_array());
//     //         let enc = aes::encrypt(padded, self.shared_secret.unwrap(), iv, aes::Mode::CBC);

//     //         EncMessage { iv, message: enc }
//     //     }

//     //     fn dec(&self, enc_msg: EncMessage) -> Vec<u8> {
//     //         let EncMessage { iv, message: enc } = enc_msg;

//     //         let mut dec = aes::decrypt(enc, self.shared_secret.unwrap(), iv, aes::Mode::CBC);
//     //         pkcs7_unpad_owned(&mut dec).unwrap();
//     //         dec
//     //     }
//     // }

//     fn diffie_hellman<A: Party, B: Party>(msg: &[u8], mut rng: impl Rng32) {
//         let mut a = A::new(&mut rng);
//         let mut b = B::new(&mut rng);

//         let init = a.init();
//         let ack = b.ack(init);
//         let a_pub = a.send_pub(ack);
//         let b_pub = b.reply_pub(a_pub);
//         a.recv_pub(b_pub);

//         let a_to_a = a.dec(a.enc(msg));
//         let a_to_b = a.dec(b.enc(msg));
//         let b_to_a = b.dec(a.enc(msg));
//         let b_to_b = b.dec(b.enc(msg));

//         assert_eq!(a_to_a, msg);
//         assert_eq!(a_to_b, msg);
//         assert_eq!(b_to_a, msg);
//         assert_eq!(b_to_b, msg);
//     }

//     // fn mitm<A: Party, B: Party, M: Party>(msg: &[u8], mut rng: impl Rng32) {
//     //     let mut a = A::new(&mut rng);
//     //     let mut b = B::new(&mut rng);
//     //     let mut m = M::new(&mut rng);

//     //     let a_init = a.init();
//     //     let m_init = m.init();

//     //     let m_resp = m.resp_pub(a_init);
//     //     a.recv_pub(m_resp);

//     //     let b_resp = b.resp_pub(m_init);
//     //     m.recv_pub(b_resp);

//     //     let a_enc = a.enc(msg);
//     //     let m_dec = m.dec(a_enc.clone());
//     //     let b_dec = b.dec(a_enc);

//     //     assert_eq!(m_dec, msg);
//     //     assert_eq!(b_dec, msg);
//     // }

//     #[test]
//     fn challenge35() {
//         let mut rng = XorShift32::new();

//         diffie_hellman::<Honest, Honest>(b"My name is jeff and I love to eat socks", &mut rng);
//         // mitm::<Honest, Honest, Malicious>(b"My name is socks and I love to eat jeff", &mut rng);
//     }
// }
