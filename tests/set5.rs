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
