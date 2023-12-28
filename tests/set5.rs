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

// mod chall24 {
//     // use std::sync::mpsc;

//     use rusty_pals::crypto::aes::Iv;

//     use super::*;

//     struct Initial {
//         pub_key: Bigint,
//         generator: Bigint,
//         modulus: Bigint,
//     }

//     struct ResponsePublicKey {
//         key: Bigint,
//     }

//     struct EncMessage {
//         iv: Iv,
//         message: Vec<u8>,
//     }

//     trait Party {
//         fn new(rng: impl Rng32) -> Self;

//         fn init(&mut self) -> Initial;
//         fn resp_pub(&mut self, init: Initial) -> ResponsePublicKey;
//         fn recv_pub(&mut self, resp_pub: ResponsePublicKey);

//         fn enc(&self, msg: &[u8]) -> EncMessage;
//         fn dec(&self, enc_msg: EncMessage) -> Vec<u8>;
//     }

//     // fn test_diffie_hellman<A: Party, B: Party>(msg: &[u8], mut rng: impl Rng32) {
//     //     let mut a = A::new(rng);
//     //     let mut b = A::new(rng);

//     //     let init = a.init();
//     //     let resp = b.resp_pub(init);
//     //     a.recv_pub(resp);

//     //     let enc_a = a.enc(msg);
//     //     let enc_b = b.enc(msg);

//     //     let a_to_a = a.dec(enc_a);
//     //     let a_to_b = a.dec(enc_b);
//     //     let b_to_a = b.dec(enc_a);
//     //     let b_to_b = b.dec(enc_b);

//     //     assert_eq!(a_to_a, msg);
//     //     assert_eq!(a_to_b, msg);
//     //     assert_eq!(b_to_a, msg);
//     //     assert_eq!(b_to_b, msg);
//     // }

//     #[test]
//     fn challenge34() {
//         let mut rng = XorShift32::new();

//         todo!()
//     }
// }
