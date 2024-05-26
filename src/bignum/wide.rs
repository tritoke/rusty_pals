use super::Bignum;
use std::ops::{Rem, RemAssign};

/// A double wide bignum used to store the result of operations that have a double wide result
/// For example multiplcation / squaring
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct WideBignum<const LIMBS: usize> {
    /// The most significant half of the number
    hi: Bignum<LIMBS>,
    /// The least significant half of the number
    lo: Bignum<LIMBS>,
}

impl<const LIMBS: usize> PartialEq<Bignum<LIMBS>> for WideBignum<LIMBS> {
    fn eq(&self, other: &Bignum<LIMBS>) -> bool {
        self.hi.is_zero() && &self.lo == other
    }
}

impl<const LIMBS: usize> PartialOrd<Bignum<LIMBS>> for WideBignum<LIMBS> {
    fn partial_cmp(&self, other: &Bignum<LIMBS>) -> Option<std::cmp::Ordering> {
        // if the high limb isn't zero it is always bigger
        if !self.hi.is_zero() {
            Some(std::cmp::Ordering::Greater)
        } else {
            self.lo.partial_cmp(other)
        }
    }
}

impl<const LIMBS: usize> WideBignum<LIMBS> {
    pub const ZERO: Self = Self {
        hi: Bignum::ZERO,
        lo: Bignum::ZERO,
    };

    pub fn new(high: Bignum<LIMBS>, low: Bignum<LIMBS>) -> Self {
        Self { hi: high, lo: low }
    }

    pub fn split(self) -> (Bignum<LIMBS>, Bignum<LIMBS>) {
        (self.hi, self.lo)
    }

    fn leading_zeros(&self) -> u32 {
        if self.lo.is_zero() {
            self.hi.leading_zeros() + self.lo.leading_zeros()
        } else {
            self.lo.leading_zeros()
        }
    }

    fn shl_with_overflow(&mut self, rhs: u32) -> bool {
        if rhs as usize >= LIMBS * 2 * 64 {
            *self = Self::ZERO;
            return true;
        }

        if rhs == 0 {
            return false;
        }

        let mut lo = self.lo;
        let hi = if dbg!(lo.shl_with_overflow(rhs)) {
            self.lo << (rhs - (LIMBS as u32 * 64))
        } else {
            (self.hi << rhs) | (self.lo >> (LIMBS as u32 * 64 - rhs))
        };

        *self = WideBignum { hi, lo };

        false
    }

    // fn remainder(self, modulus: &Bignum<LIMBS>) -> Bignum<LIMBS> {
    //     debug_assert!(!modulus.is_zero(), "attempt to divide by zero");

    //     // early exit for simple cases - CT is hard lmao
    //     if modulus.is_one() {
    //         return Bignum::ZERO;
    //     }

    //     if &self < modulus {
    //         return self.lo;
    //     }

    //     let mut dividend = self;
    //     let mut divisor = WideBignum::new(Bignum::ZERO, *modulus);

    //     // normalise divisor
    //     let normalising_shift = divisor.leading_zeros() - dividend.leading_zeros();
    //     divisor <<= normalising_shift;
    //     debug_assert_eq!(dividend.leading_zeros(), divisor.leading_zeros());

    //     // initialize quotient and remainder
    //     let mut quotient = Bignum::ZERO;

    //     // perform the division
    //     while &dividend >= modulus {
    //         quotient <<= 1;
    //         if dividend >= divisor {
    //             dividend -= divisor;
    //             quotient |= Bignum::ONE;
    //         }
    //         divisor >>= 1;
    //     }

    //     dividend
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shl_wide_bignums() {
        const LIMBS: usize = 10;

        for i in 0..2 * LIMBS as u32 {
            let lo: Bignum<LIMBS> = Bignum::MAX;
            let hi: Bignum<LIMBS> = Bignum::ZERO;
            let mut wide = WideBignum { hi, lo };

            assert!(!wide.shl_with_overflow(i * 64));

            let correct = if i < LIMBS as u32 {
                WideBignum {
                    hi: if i == 0 {
                        Bignum::ZERO
                    } else {
                        Bignum::MAX >> ((LIMBS as u32 - i) * 64)
                    },
                    lo: if i == 0 {
                        Bignum::MAX
                    } else {
                        Bignum::MAX << (i * 64)
                    },
                }
            } else {
                WideBignum {
                    hi: if i == LIMBS as u32 * 64 {
                        Bignum::MAX
                    } else {
                        Bignum::MAX << ((i - LIMBS as u32) * 64)
                    },
                    lo: Bignum::ZERO,
                }
            };

            assert_eq!(correct, wide);
        }
    }
}
