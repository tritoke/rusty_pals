use crate::rand::XorShift32;

use super::{Bignum, MontyInfo};

pub enum PrimalityTestResult {
    ProbablePrime,
    Composite,
}

impl<const LIMBS: usize> Bignum<LIMBS> {
    fn is_probable_prime(&self, iterations: u32) -> PrimalityTestResult {
        if self.is_even() {
            return PrimalityTestResult::Composite;
        }

        // factor into s (power of 2) and d (odd)
        let s = self.trailing_zeros();
        let d = self >> s;

        debug_assert!(d.is_odd());

        let mut rng = XorShift32::new();
        for _ in 0..iterations {
            // I mean its probably not 0,1,n,n-1 lol
            let mut a = Bignum::random(&mut rng);
            a &= self;

            let mut x = a.modexp(d, *self);
            for _ in 0..s {
                // let y = x.square_wide
            }
        }

        todo!()
    }

    fn gen_prime(bits: u32) -> (Bignum<LIMBS>, MontyInfo<LIMBS>) {
        todo!()
    }
}
