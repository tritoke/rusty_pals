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
        if rhs as usize >= LIMBS * 64 {
            *self = Self::ZERO;
            return true;
        }

        // we have 64 * LIMBS total bits
        // a shift of N bits moves the top 64 * LIMBS - N bits to the lowest bits
        // meaning the lowest eventual limb is
        let bottom_limb = rhs as usize / 64;
        let limb_split_pos = rhs % 64;

        // we can optimise for word aligned shifts
        if limb_split_pos == 0 {
            // split into three copies
            // within self.hi
            self.hi
                .limbs
                .copy_within(0..LIMBS - bottom_limb, bottom_limb);
            // between self.lo and self.hi
            self.hi
                .limbs
                [LIMBS-bottom_limb..]
               .copy_from_slice(src)
            // within self.lo
            self.lo
                .limbs
                .copy_within(0..LIMBS - bottom_limb, bottom_limb);
        } else {
            for i in (bottom_limb + 1..LIMBS).rev() {
                let upper = self.limbs[i - bottom_limb] << limb_split_pos;
                let lower = self.limbs[i - bottom_limb - 1] >> (64 - limb_split_pos);
                self.limbs[i] = upper | lower;
            }

            self.limbs[bottom_limb] = self.limbs[0] << limb_split_pos;
        }

        for i in 0..bottom_limb {
            self.limbs[i] = 0;
        }

        false
    }

    fn remainder(self, modulus: &Bignum<LIMBS>) -> Bignum<LIMBS> {
        debug_assert!(!modulus.is_zero(), "attempt to divide by zero");

        // early exit for simple cases - CT is hard lmao
        if modulus.is_one() {
            return Bignum::ZERO;
        }

        if &self < modulus {
            return self.lo;
        }

        let mut dividend = self;
        let mut divisor = WideBignum::new(Bignum::ZERO, *modulus);

        // normalise divisor
        let normalising_shift = divisor.leading_zeros() - dividend.leading_zeros();
        divisor <<= normalising_shift;
        debug_assert_eq!(dividend.leading_zeros(), divisor.leading_zeros());

        // initialize quotient and remainder
        let mut quotient = Bignum::ZERO;

        // perform the division
        while &dividend >= modulus {
            quotient <<= 1;
            if dividend >= divisor {
                dividend -= divisor;
                quotient |= Bignum::ONE;
            }
            divisor >>= 1;
        }

        dividend
    }
}
