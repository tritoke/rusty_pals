use crate::rand::XorShift32;

use super::Bignum;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimalityTestResult {
    ProbablePrime,
    Composite,
}

impl<const LIMBS: usize> Bignum<LIMBS> {
    fn primality_test(&self, iterations: u32) -> PrimalityTestResult {
        if self.is_even() {
            return if *self == Bignum::from(2u8) {
                PrimalityTestResult::ProbablePrime
            } else {
                PrimalityTestResult::Composite
            };
        }

        // factor into s (power of 2) and r (odd)
        let n_minus_1 = self - Bignum::ONE;
        let s = n_minus_1.trailing_zeros();
        let r = n_minus_1 >> s;
        let rng_mask = Bignum::MAX >> self.leading_zeros();

        debug_assert!(r.is_odd());

        let mut rng = XorShift32::new();
        for _ in 0..iterations {
            let a = loop {
                let cand = Bignum::random(&mut rng) & rng_mask | Bignum::ONE;
                if cand > Bignum::ONE && cand < n_minus_1 {
                    break cand;
                }
            };

            let mut y = a.modexp(r, *self);
            if !y.is_one() && y != n_minus_1 {
                for _ in 0..s {
                    if y == n_minus_1 {
                        break;
                    }

                    y = y.square_wide().remainder(self);
                    if y.is_one() {
                        return PrimalityTestResult::Composite;
                    }
                }

                if y != n_minus_1 {
                    return PrimalityTestResult::Composite;
                }
            }
        }

        PrimalityTestResult::ProbablePrime
    }

    fn gen_prime(bits: u32) -> Bignum<LIMBS> {
        let mask = Bignum::MAX >> (LIMBS as u32 * 64 - bits);

        let mut rng = XorShift32::new();
        loop {
            let cand = Bignum::random(&mut rng) & mask;

            if cand.primality_test(40) == PrimalityTestResult::ProbablePrime {
                break cand;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_primality_test_for_7() {
        let prime: Bignum<8> = "0x7".parse().unwrap();

        assert_eq!(prime.primality_test(10), PrimalityTestResult::ProbablePrime);
    }

    #[test]
    fn test_primality_test_for_prime() {
        let prime: Bignum<8> = "0xcfc683dd8dc1861cc0e144df73b76ab9e7d87c2b0323e0e3ec41468d0d16e623f7c16bf09d6197a6e043e59ad97e85631d9953073b3d044e26ba06e3feca6d9b".parse().unwrap();

        assert_eq!(prime.primality_test(10), PrimalityTestResult::ProbablePrime);
    }

    #[test]
    fn test_primality_test_for_composite() {
        let prime: Bignum<8> = "0xcfc683dd8dc1861cc0e143df73b76ab9e7d87c2b0323e0e3ec41468d0d16e623f7c16bf09d6197a6e043e59ad97e85631d9953073b3d044e26ba06e3feca6d9b".parse().unwrap();

        assert_eq!(prime.primality_test(10), PrimalityTestResult::Composite);
    }

    #[test]
    fn test_gen_prime_generates_a_prime() {
        assert_eq!(
            Bignum::<10>::gen_prime(100).primality_test(10),
            PrimalityTestResult::ProbablePrime
        );
    }
}
