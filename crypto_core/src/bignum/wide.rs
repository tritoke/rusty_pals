use super::Bignum;

/// A double wide bignum used to store the result of operations that have a double wide result
/// For example multiplcation / squaring
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub(super) struct WideBignum<const LIMBS: usize> {
    /// The most significant half of the number
    hi: Bignum<LIMBS>,
    /// The least significant half of the number
    lo: Bignum<LIMBS>,
}

impl<const LIMBS: usize> PartialOrd for WideBignum<LIMBS> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const LIMBS: usize> Ord for WideBignum<LIMBS> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hi.cmp(&other.hi).then_with(|| self.lo.cmp(&other.lo))
    }
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

#[allow(unused)]
impl<const LIMBS: usize> WideBignum<LIMBS> {
    pub const ZERO: Self = Self {
        hi: Bignum::ZERO,
        lo: Bignum::ZERO,
    };

    pub const MAX: Self = Self {
        hi: Bignum::MAX,
        lo: Bignum::MAX,
    };

    pub const MIN: Self = Self::ZERO;

    pub fn new(high: Bignum<LIMBS>, low: Bignum<LIMBS>) -> Self {
        Self { hi: high, lo: low }
    }

    pub fn new_low(limb: Bignum<LIMBS>) -> Self {
        Self {
            hi: Bignum::ZERO,
            lo: limb,
        }
    }

    pub fn new_high(limb: Bignum<LIMBS>) -> Self {
        Self {
            hi: limb,
            lo: Bignum::ZERO,
        }
    }

    pub fn split(self) -> (Bignum<LIMBS>, Bignum<LIMBS>) {
        (self.hi, self.lo)
    }

    fn leading_zeros(&self) -> u32 {
        if self.hi.is_zero() {
            self.hi.leading_zeros() + self.lo.leading_zeros()
        } else {
            self.hi.leading_zeros()
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
        let hi = if lo.shl_with_overflow(rhs) {
            self.lo << (rhs - (LIMBS as u32 * 64))
        } else {
            (self.hi << rhs) | (self.lo >> (LIMBS as u32 * 64 - rhs))
        };

        *self = WideBignum { hi, lo };

        false
    }

    fn shr_with_overflow(&mut self, rhs: u32) -> bool {
        if rhs as usize >= LIMBS * 2 * 64 {
            *self = Self::ZERO;
            return true;
        }

        if rhs == 0 {
            return false;
        }

        let mut hi = self.hi;
        let lo = if hi.shr_with_overflow(rhs) {
            self.hi >> (rhs - (LIMBS as u32 * 64))
        } else {
            (self.lo >> rhs) | (self.hi << (LIMBS as u32 * 64 - rhs))
        };

        *self = WideBignum { lo, hi };

        false
    }

    fn sub_with_overflow(&mut self, rhs: &Self) -> bool {
        let carry = self.lo.sub_with_overflow(&rhs.lo);
        self.hi.borrowing_sub_with_overflow(&rhs.hi, carry)
    }

    pub fn remainder(self, modulus: &Bignum<LIMBS>) -> Bignum<LIMBS> {
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
        divisor.shl_with_overflow(normalising_shift);
        debug_assert_eq!(dividend.leading_zeros(), divisor.leading_zeros());

        // perform the division
        while &dividend >= modulus {
            if dividend >= divisor {
                dividend.sub_with_overflow(&divisor);
            }
            divisor.shr_with_overflow(1);
        }

        let (hi, lo) = dividend.split();
        assert!(hi.is_zero());
        lo
    }
}

#[cfg(test)]
mod tests {
    use crate::bignum::nist;

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

    #[test]
    fn test_shr_wide_bignums() {
        const LIMBS: usize = 10;

        for i in 0..2 * LIMBS as u32 {
            let lo: Bignum<LIMBS> = Bignum::ZERO;
            let hi: Bignum<LIMBS> = Bignum::MAX;
            let mut wide = WideBignum { hi, lo };

            assert!(!wide.shr_with_overflow(i * 64));

            let correct = if i < LIMBS as u32 {
                WideBignum {
                    hi: if i == 0 {
                        Bignum::MAX
                    } else {
                        Bignum::MAX >> (i * 64)
                    },
                    lo: if i == 0 {
                        Bignum::ZERO
                    } else {
                        Bignum::MAX << ((LIMBS as u32 - i) * 64)
                    },
                }
            } else {
                WideBignum {
                    hi: Bignum::ZERO,
                    lo: if i == LIMBS as u32 * 64 {
                        Bignum::MAX
                    } else {
                        Bignum::MAX >> ((i - LIMBS as u32) * 64)
                    },
                }
            };

            assert_eq!(correct, wide);
        }
    }

    #[test]
    fn test_leading_zeros_bignums() {
        let a: WideBignum<10> = WideBignum {
            hi: Bignum {
                limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
            },
            lo: Bignum::ZERO,
        };
        assert_eq!(a.leading_zeros(), 64);

        let a: WideBignum<10> = WideBignum {
            hi: Bignum::ZERO,
            lo: Bignum {
                limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
            },
        };
        assert_eq!(a.leading_zeros(), 64 * 11);

        assert_eq!(WideBignum::<10>::MIN.leading_zeros(), 64 * 10 * 2);
        assert_eq!(WideBignum::<10>::MAX.leading_zeros(), 0);
        let mut a = WideBignum::<10>::MAX;
        a.shr_with_overflow(50);
        assert_eq!(a.leading_zeros(), 50);
    }

    #[test]
    fn test_sub_wide_bignums() {
        let a: WideBignum<10> = WideBignum {
            hi: Bignum::ZERO,
            lo: 5u8.into(),
        };
        let mut b: WideBignum<10> = WideBignum {
            hi: Bignum::ZERO,
            lo: 6u8.into(),
        };
        b.sub_with_overflow(&a);
        assert_eq!(b.lo, 1u8.into());
        assert!(b.hi.is_zero());

        let mut a: WideBignum<10> = WideBignum {
            hi: Bignum::ZERO,
            lo: Bignum {
                limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            },
        };
        let b: WideBignum<10> = WideBignum {
            hi: Bignum::ZERO,
            lo: 1u8.into(),
        };
        a.sub_with_overflow(&b);
        assert_eq!(a.lo, u64::MAX.into());
        assert!(a.hi.is_zero());

        let mut a: WideBignum<10> = WideBignum::MAX;
        let b: WideBignum<10> = WideBignum::MAX;
        a.sub_with_overflow(&b);
        assert!(a.lo.is_zero() && a.hi.is_zero());

        let mut a: WideBignum<10> = WideBignum {
            hi: Bignum::MAX,
            lo: Bignum::ZERO,
        };
        let b: WideBignum<10> = WideBignum {
            hi: Bignum::ZERO,
            lo: Bignum::MAX,
        };
        a.sub_with_overflow(&b);

        let mut correct_hi = Bignum::MAX;
        correct_hi -= Bignum::from(1u8);

        assert_eq!(
            a,
            WideBignum {
                hi: correct_hi,
                lo: Bignum::ONE
            }
        );
    }

    #[test]
    fn test_rem_wide_bignums() {
        let rmdr = WideBignum::MAX.remainder(&nist::NIST_P);
        let correct: Bignum<24> = "0xe3b33c7259541c01ee9c9a216cc1ebd2ae5941047929a1c7e9c3fa02cc2456ef102630fa9a36a51f57b59348679844600be49647a87c7b37f8056564969b7f02dc541a4ed4053f54d62a0eeab270521b22c296e9d46fec238e1abd780223b76bb8fe6121196b7e881c729c7e04b9f79607cd0a628e43413004a541ff93ae1cebb004a750db102d39b9052bb47a58f1707e8cd2ac98b5fb628f2331b13b01e018f466ee5fbcd49d68d0ab92e18397f2458e0e3e2167478c73f115d27d32c695df".parse().unwrap();
        assert_eq!(correct, rmdr);
    }
}
