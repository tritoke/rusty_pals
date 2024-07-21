#![allow(clippy::clone_on_copy)]

//! THE BIBLE: <https://cacr.uwaterloo.ca/hac/about/chap14.pdf>

use crate::rand::Rng32;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

mod arith;

mod monty;
pub use monty::{MontyForm, MontyInfo};

mod wide;
pub use wide::WideBignum;

pub mod nist;

mod primality;
pub use primality::PrimalityTestResult;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Bignum<const LIMBS: usize> {
    limbs: [u64; LIMBS],
}

impl<const LIMBS: usize> AsRef<[u8]> for Bignum<LIMBS> {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: I mean whats a u64 but 8 u8 in a trenchcoat anyway??
        unsafe { std::mem::transmute(&self.limbs[..]) }
    }
}

/// Public utility functions
impl<const LIMBS: usize> Bignum<LIMBS> {
    pub const MAX: Self = Self {
        limbs: [u64::MAX; LIMBS],
    };

    pub const MIN: Self = Self {
        limbs: [u64::MIN; LIMBS],
    };

    pub const ZERO: Self = Self::MIN;

    pub const ONE: Self = {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = 1;
        Bignum { limbs }
    };

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|x| *x == 0)
    }

    pub fn is_one(&self) -> bool {
        self.limbs[0] == 1 && self.limbs.iter().skip(1).all(|x| *x == 0)
    }

    pub fn count_ones(&self) -> u32 {
        self.limbs.iter().map(|limb| limb.count_ones()).sum()
    }

    pub fn count_zeros(&self) -> u32 {
        self.limbs.iter().map(|limb| limb.count_zeros()).sum()
    }

    pub fn leading_zeros(&self) -> u32 {
        let one_pos = self
            .limbs
            .iter()
            .rev()
            .take_while(|&&limb| limb == 0)
            .count();
        let final_limb_leading_ones = self
            .limbs
            .get((LIMBS - one_pos).wrapping_sub(1))
            .unwrap_or(&u64::MAX)
            .leading_zeros();
        one_pos as u32 * 64 + final_limb_leading_ones
    }

    pub fn trailing_zeros(&self) -> u32 {
        let one_pos = self.limbs.iter().take_while(|&&limb| limb == 0).count();
        let final_limb_trailing_zeros = self
            .limbs
            .get(one_pos)
            .unwrap_or(&u64::MAX)
            .trailing_zeros();
        one_pos as u32 * 64 + final_limb_trailing_zeros
    }

    pub fn leading_ones(&self) -> u32 {
        let zero_pos = self
            .limbs
            .iter()
            .rev()
            .take_while(|&&limb| limb == u64::MAX)
            .count();
        let final_limb_leading_ones = self
            .limbs
            .get((LIMBS - zero_pos).wrapping_sub(1))
            .unwrap_or(&0)
            .leading_ones();
        zero_pos as u32 * 64 + final_limb_leading_ones
    }

    pub fn trailing_ones(&self) -> u32 {
        let zero_pos = self
            .limbs
            .iter()
            .take_while(|&&limb| limb == u64::MAX)
            .count();
        let final_limb_trailing_ones = self.limbs.get(zero_pos).unwrap_or(&0).trailing_ones();
        zero_pos as u32 * 64 + final_limb_trailing_ones
    }

    /// The number of bits required to represent this number
    pub fn bit_length(&self) -> u32 {
        64 * LIMBS as u32 - self.leading_zeros()
    }

    /// Test if bit N is set
    pub fn test_bit(&self, bit: usize) -> bool {
        debug_assert!(bit < 64 * LIMBS, "attempt to test bit with overflow");

        let limb_idx = bit / 64;
        let bit_idx = bit % 64;

        (self.limbs[limb_idx] >> bit_idx) & 1 == 1
    }

    /// performs both division and mod and returns the pair (div, mod)
    pub fn divmod(&self, rhs: &Self) -> (Self, Self) {
        debug_assert!(!rhs.is_zero(), "attempt to divide by zero");

        // early exit for simple cases - CT is hard lmao
        if rhs.is_one() {
            return (*self, Bignum::ZERO);
        }

        if rhs > self {
            return (Bignum::ZERO, *self);
        }

        let mut dividend = *self;
        let mut divisor = *rhs;

        // normalise divisor
        let normalising_shift = divisor.leading_zeros() - dividend.leading_zeros();
        divisor <<= normalising_shift;
        debug_assert_eq!(dividend.leading_zeros(), divisor.leading_zeros());

        // initialize quotient and remainder
        let mut quotient = Bignum::ZERO;

        // perform the division
        while &dividend >= rhs {
            quotient <<= 1;
            if dividend >= divisor {
                dividend -= divisor;
                quotient |= Bignum::ONE;
            }
            divisor >>= 1;
        }
        let remainder = dividend;
        quotient <<= 1 + divisor.bit_length() - rhs.bit_length();

        (quotient, remainder)
    }

    /// The div part of the divmod
    pub fn quotient(&mut self, rhs: &Self) {
        *self = self.divmod(rhs).0;
    }

    /// The mod part of the divmod
    pub fn remainder(&mut self, rhs: &Self) {
        *self = self.divmod(rhs).1;
    }

    /// Perform multipliction into a wide result
    pub fn mul_wide(&self, rhs: &Self) -> WideBignum<LIMBS> {
        let mut out = WideBignum::ZERO;

        for (i, r) in rhs.limbs.iter().enumerate() {
            let mut carry = 0;
            for (l, o) in self
                .limbs
                .iter()
                .chain(std::iter::repeat(&0))
                .zip(out.limbs_mut().skip(i))
            {
                let (prod, next_carry) = arith::carrying_mul(*r, *l, carry);
                let (new_limb, add_carry) = o.overflowing_add(prod);
                carry = next_carry + u64::from(add_carry);
                *o = new_limb;
            }
            debug_assert_eq!(carry, 0);
        }

        out
    }

    /// Perform squaring into a wide results
    pub fn square_wide(&self) -> WideBignum<LIMBS> {
        let mut out = WideBignum::ZERO;

        let mut lagged_carry = false;
        for i in 0..LIMBS {
            let xi = self.limbs[i] as u128;
            let wi = out.limb(i * 2) as u128;
            let mut uv = wi + xi * xi;
            *out.limb_mut(i * 2) = uv as u64;
            let mut c = uv >> 64;
            let mut carry = false;
            for j in i + 1..LIMBS {
                let xj = self.limbs[j] as u128;
                let wij = out.limb(i + j) as u128;
                let partial = xj * xi;

                // split the computation into two which cannot overflow and combine handling the
                // overflow

                (uv, carry) =
                    (wij + c + partial).overflowing_add(partial + ((carry as u128) << 64));
                *out.limb_mut(i + j) = uv as u64;
                c = uv >> 64;
            }

            *out.limb_mut(i + LIMBS) = c as u64 + lagged_carry as u64;
            lagged_carry = carry;
        }

        debug_assert!(!lagged_carry);

        out
    }

    /// Raise self to the power exponent remainder modulus
    pub fn modexp(self, exponent: Self, modulus: Self) -> Self {
        debug_assert!(self.bit_length() <= LIMBS as u32 * 32);
        debug_assert!(modulus.bit_length() <= LIMBS as u32 * 32);

        if exponent.is_zero() {
            return Bignum::ONE;
        }

        let mut x = self;
        let mut y = Bignum::ONE;
        for i in 0..(exponent.bit_length() as usize - 1) {
            if exponent.test_bit(i) {
                y = (y * x) % modulus;
            }
            x = (x * x) % modulus;
        }

        (x * y) % modulus
    }

    /// Generate a uniformly random Bignum from Bignum::MIN to Bignum::MAX inclusive
    pub fn random(mut rng: impl Rng32) -> Self {
        let mut out = Self::ZERO;
        for limb in out.limbs.iter_mut() {
            *limb = u64::from_be_bytes(rng.gen_array());
        }
        out
    }

    /// Is the number even
    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    /// Is the number odd
    pub fn is_odd(&self) -> bool {
        !self.is_even()
    }

    /// Increase the number of limbs filling the new limbs with zero
    pub fn widen<const OUT_LIMBS: usize>(&self) -> Bignum<OUT_LIMBS> {
        let mut out: Bignum<OUT_LIMBS> = Bignum::ZERO;
        out.limbs[..LIMBS].copy_from_slice(&self.limbs);
        out
    }

    /// Decrease the number of limbs, ignoring limbs past the end
    pub fn narrow<const OUT_LIMBS: usize>(&self) -> Bignum<OUT_LIMBS> {
        let mut out: Bignum<OUT_LIMBS> = Bignum::ZERO;
        out.limbs.copy_from_slice(&self.limbs[..OUT_LIMBS]);
        out
    }
}

impl<const LIMBS: usize> Bignum<LIMBS> {
    /// Compute the extended greated common divisor algorithm between x and y
    #[allow(non_snake_case)]
    fn xgcd(mut x: Self, mut y: Self) -> (Self, Self, Self) {
        debug_assert!(x.is_odd() || y.is_odd());
        debug_assert!(!x.is_zero());
        debug_assert!(!y.is_zero());

        let mut g = Self::ONE;
        while x.is_even() && y.is_even() {
            g <<= 1;
            x >>= 1;
            y >>= 1;
        }

        let mut u = x;
        let mut v = y;
        let mut A = Self::ONE;
        let mut B = Self::ZERO;
        let mut C = Self::ZERO;
        let mut D = Self::ONE;

        while !u.is_zero() {
            while u.is_even() {
                u >>= 1;

                if A.is_odd() || B.is_odd() {
                    A.add_with_overflow(&y);
                    B.sub_with_overflow(&x);
                }

                A.arithmetic_shr_with_overflow(1);
                B.arithmetic_shr_with_overflow(1);
            }

            while v.is_even() {
                v >>= 1;

                if C.is_odd() || D.is_odd() {
                    C.add_with_overflow(&y);
                    D.sub_with_overflow(&x);
                }

                C.arithmetic_shr_with_overflow(1);
                D.arithmetic_shr_with_overflow(1);
            }

            if u >= v {
                u -= &v;
                A.sub_with_overflow(&C);
                B.sub_with_overflow(&D);
            } else {
                v -= &u;
                C.sub_with_overflow(&A);
                D.sub_with_overflow(&B);
            }
        }

        g *= &v;

        (C, D, g)
    }

    pub fn inv_mod(&self, modulus: &Self) -> Self {
        let (x, _y, gcd) = Self::xgcd(*self, *modulus);
        debug_assert!(gcd.is_one());

        x
    }
}

impl<const LIMBS: usize> Default for Bignum<LIMBS> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const LIMBS: usize> fmt::Display for Bignum<LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0x0");
        }

        let num = if f.alternate() && self.is_negative() {
            write!(f, "-")?;
            -self
        } else {
            *self
        };

        let mut first = true;
        for limb in num.limbs.iter().rev() {
            if first && *limb != 0 {
                write!(f, "0x{limb:x}")?;
                first = false;
            } else if !first {
                write!(f, "{limb:016x}")?;
            }
        }

        Ok(())
    }
}

impl<const LIMBS: usize> FromStr for Bignum<LIMBS> {
    type Err = ParseIntError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        let negate = s.starts_with('-');
        s = s.strip_prefix('-').unwrap_or(s);
        s = s.strip_prefix("0x").unwrap_or(s);
        let offset = if s.starts_with("0x") { 2 } else { 0 };
        let bytes = &s.as_bytes()[offset..];
        if bytes.len() > LIMBS * 16 {
            return Err(u8::from_str("-1").unwrap_err());
        }

        let mut out = Self::ZERO;
        for (limb, chunk) in out.limbs.iter_mut().zip(bytes.rchunks(16)) {
            *limb = u64::from_str_radix(
                std::str::from_utf8(chunk).expect("MMH WHY IS THERE UNICODE IN YOUR NUMBER BOI"),
                16,
            )?;
        }

        if negate {
            out.negate();
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_bignums() {
        let nums: [Bignum<10>; 5] = [
            Bignum::ZERO,
            5u8.into(),
            u64::MAX.into(),
            Bignum {
                limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            },
            Bignum {
                limbs: [u64::MAX; 10],
            },
        ];
        let strings = ["0x0", "0x5", "0xffffffffffffffff", "0x10000000000000000", "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"];

        for (n, s) in nums.iter().zip(strings.iter()) {
            assert_eq!(format!("{n}"), *s);
        }
    }

    #[test]
    fn test_from_str_bignums() {
        let p1: Bignum<24> = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".parse().unwrap();
        let p2: Bignum<24> = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".parse().unwrap();
        assert_eq!(p1, super::nist::NIST_P);
        assert_eq!(p2, super::nist::NIST_P);

        let correct = Bignum {
            limbs: [
                0x5183BFDDCCA23D70,
                0xC1135A30B0C946F6,
                0x57371B24B6F2D945,
                0xE7A57F3554F2B629,
                0x8690EE841B90377C,
                0xF73741ABF0A9E539,
                0x3A9B3E5742132723,
                0x472C2B2501532630,
                0xC96DA6DF68EE7524,
                0x058A7A855EBF6254,
                0x8928B75CA0A8B9EB,
                0xC33ED8C7D0364E36,
                0x10903C107A7B7B56,
                0xC65145A1CC28F4F1,
                0xF134CB141FA214D6,
                0xAE30538BEA04662B,
                0x03711C8F4FEA262C,
                0x448253B4FE7F4CDD,
                0x7AC68A579E47815E,
                0x29BA7A643004167D,
                0xF83D2CE74601DA02,
                0x0BB582C8405B2116,
                0x164863DF9CA4B97E,
                0x0034DF1E8FB415E7,
            ],
        };

        let e: Bignum<24> = "0x34df1e8fb415e7164863df9ca4b97e0bb582c8405b2116f83d2ce74601da0229ba7a643004167d7ac68a579e47815e448253b4fe7f4cdd03711c8f4fea262cae30538bea04662bf134cb141fa214d6c65145a1cc28f4f110903c107a7b7b56c33ed8c7d0364e368928b75ca0a8b9eb058a7a855ebf6254c96da6df68ee7524472c2b25015326303a9b3e5742132723f73741abf0a9e5398690ee841b90377ce7a57f3554f2b62957371b24b6f2d945c1135a30b0c946f65183bfddcca23d70".parse().unwrap();
        assert_eq!(e, correct);
    }

    #[test]
    fn test_is_zero() {
        assert!(Bignum::<10>::MIN.is_zero());
        assert!(!Bignum::<10>::MAX.is_zero());
        assert!(Bignum::<10>::from(0u32).is_zero());
    }

    #[test]
    fn test_is_one() {
        assert!(!Bignum::<10>::MIN.is_one());
        assert!(!Bignum::<10>::MAX.is_one());
        assert!(Bignum::<10>::from(1u32).is_one());
    }

    #[test]
    fn test_count_ones_bignums() {
        let a: Bignum<10> = 0xFFFF_u16.into();
        assert_eq!(a.count_ones(), 0xFFFF_u16.count_ones());

        let a: Bignum<10> = Bignum {
            limbs: [
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
            ],
        };
        assert_eq!(a.count_ones(), u64::MAX.count_ones() * 5);
        assert_eq!(Bignum::<10>::MAX.count_ones(), u64::MAX.count_ones() * 10);
        assert_eq!(Bignum::<10>::MIN.count_ones(), 0);
    }

    #[test]
    fn test_count_zeros_bignums() {
        let a: Bignum<10> = 0xFFFF_u16.into();
        assert_eq!(
            a.count_zeros(),
            0xFFFF_u64.count_zeros() + 9 * u64::MIN.count_zeros()
        );

        let a: Bignum<10> = Bignum {
            limbs: [
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
            ],
        };
        assert_eq!(a.count_zeros(), u64::MIN.count_zeros() * 5);
        assert_eq!(Bignum::<10>::MAX.count_zeros(), 0);
        assert_eq!(Bignum::<10>::MIN.count_zeros(), 10 * u64::MIN.count_zeros());
    }

    #[test]
    fn test_leading_zeros_bignums() {
        let a: Bignum<10> = Bignum {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
        };
        assert_eq!(a.leading_zeros(), 64);
        assert_eq!(Bignum::<10>::MIN.leading_zeros(), 64 * 10);
        assert_eq!(Bignum::<10>::MAX.leading_zeros(), 0);
        assert_eq!((Bignum::<10>::MAX >> 50).leading_zeros(), 50);
        for i in 0..64 {
            let a: Bignum<10> = Bignum {
                limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, u64::MAX >> i],
            };
            assert_eq!(a.leading_zeros(), i);
        }
    }

    #[test]
    fn test_trailing_zeros_bignums() {
        let a: Bignum<10> = Bignum {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
        };
        assert_eq!(a.trailing_zeros(), 64 * 8);
        assert_eq!(Bignum::<10>::MIN.trailing_zeros(), 64 * 10);
        assert_eq!(Bignum::<10>::MAX.trailing_zeros(), 0);
        assert_eq!((Bignum::<10>::MAX << 50).trailing_zeros(), 50);
    }

    #[test]
    fn test_leading_ones_bignums() {
        let a: Bignum<10> = Bignum {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, 0, u64::MAX],
        };
        assert_eq!(a.leading_ones(), 64);
        assert_eq!(Bignum::<10>::MIN.leading_ones(), 0);
        assert_eq!(Bignum::<10>::MAX.leading_ones(), 64 * 10);
        assert_eq!((!(Bignum::<10>::MAX >> 50)).leading_ones(), 50);
    }

    #[test]
    fn test_trailing_ones_bignums() {
        let a: Bignum<10> = !Bignum {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
        };
        assert_eq!(a.trailing_ones(), 64 * 8);
        assert_eq!(Bignum::<10>::MIN.trailing_ones(), 0);
        assert_eq!(Bignum::<10>::MAX.trailing_ones(), 64 * 10);
        assert_eq!((!(Bignum::<10>::MAX << 50)).trailing_ones(), 50);
    }

    #[test]
    fn test_bit_length_bignums() {
        let a: Bignum<10> = Bignum {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
        };
        assert_eq!(a.bit_length(), 64 * 9);
        assert_eq!(Bignum::<10>::MIN.bit_length(), 0);
        assert_eq!(Bignum::<10>::MAX.bit_length(), 64 * 10);
        assert_eq!((Bignum::<10>::MAX >> 50).bit_length(), 64 * 10 - 50);
    }

    #[test]
    fn test_test_bit_bignums() {
        let a: Bignum<10> = Bignum {
            limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
        };
        for i in 0..640 {
            assert!(Bignum::<10>::MAX.test_bit(i));
            assert!(!Bignum::<10>::MIN.test_bit(i));
            if (8 * 64..9 * 64).contains(&i) {
                assert!(a.test_bit(i));
            } else {
                assert!(!a.test_bit(i));
            }
        }
    }

    #[test]
    fn test_divmod_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        assert_eq!(a.divmod(&b), (0u8.into(), a));

        let a: Bignum<10> = 1234u16.into();
        let b: Bignum<10> = 56u8.into();
        assert_eq!(a.divmod(&b), (22u8.into(), 2u8.into()));

        let a: Bignum<10> = 12345_u32.into();
        let b: Bignum<10> = 10u8.into();
        assert_eq!(a.divmod(&b), (1234u16.into(), 5u8.into()));

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        assert_eq!(a.divmod(&b), (1u8.into(), Bignum::ZERO));

        let a: Bignum<10> = Bignum {
            limbs: [u64::MAX, u64::MAX, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = u64::MAX.into();
        assert_eq!(
            a.divmod(&b),
            (
                Bignum {
                    limbs: [1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                },
                Bignum::ZERO
            )
        );

        let a: Bignum<10> = Bignum::MAX;
        let b: Bignum<10> = u64::MAX.into();
        assert_eq!(a.divmod(&b), (Bignum { limbs: [1; 10] }, Bignum::ZERO));
    }

    #[test]
    fn test_mul_wide_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        let (hi, lo) = a.mul_wide(&b).split();
        assert_eq!(lo, 30u8.into());
        assert!(hi.is_zero());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 10u8.into();
        let (hi, lo) = a.mul_wide(&b).split();
        assert_eq!(
            lo,
            Bignum {
                limbs: [0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );
        assert!(hi.is_zero());

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        let (hi, lo) = a.mul_wide(&b).split();
        assert_eq!(
            lo,
            Bignum {
                limbs: [1, u64::MAX - 1, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );
        assert!(hi.is_zero());

        let a = Bignum {
            limbs: [
                0xb4830d2b3cc4b4bb,
                0x4d847515b57d26be,
                0xf140fe29591db8b1,
                0xbfc2c416d5e95510,
                0xc1c04b03907d23ff,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
            ],
        };
        let (hi, lo) = a.mul_wide(&a).split();
        assert_eq!(
            lo,
            Bignum {
                limbs: [
                    0x623e80aee5ef8099,
                    0xfe31042acea40485,
                    0xa735be994a362d0d,
                    0x592dc17e83bc9097,
                    0x88fcd2b34c5b6749,
                    0xa546f4d2292c911a,
                    0xf623a0ab548f8545,
                    0xe6b64acd44e6d989,
                    0xa65707d712ccf8de,
                    0x92a3818bfb3082b3
                ]
            }
        );
        assert!(hi.is_zero());

        let a: Bignum<10> = Bignum::MAX;
        let b: Bignum<10> = Bignum::MAX;
        let (hi, lo) = a.mul_wide(&b).split();
        assert!(lo.is_one());
        assert_eq!(hi, Bignum::MAX - Bignum::from(1_u8));
    }

    #[test]
    fn test_square_wide_bignums() {
        let a: Bignum<10> = 5u8.into();
        let (hi, lo) = a.square_wide().split();
        assert_eq!(lo, 25u8.into());
        assert!(hi.is_zero());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let (hi, lo) = a.square_wide().split();
        assert_eq!(
            lo,
            Bignum {
                limbs: [0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            }
        );
        assert!(hi.is_zero());

        let a: Bignum<10> = Bignum::MAX;
        let (hi, lo) = a.square_wide().split();
        assert!(lo.is_one());
        assert_eq!(hi, Bignum::MAX - Bignum::from(1_u8));
    }

    #[test]
    fn test_xgcd_bignums() {
        let n: Bignum<1> = "2b5".parse().unwrap();
        let r: Bignum<1> = "261".parse().unwrap();

        let (a, b, c) = Bignum::xgcd(n, r);
        assert_eq!(a, "-0xb5".parse().unwrap());
        assert_eq!(b, "0xce".parse().unwrap());
        assert_eq!(c, "0x15".parse().unwrap());

        let (a, b, c) = Bignum::xgcd(r, n);
        assert_eq!(a, "0xad".parse().unwrap());
        assert_eq!(b, "-0x98".parse().unwrap());
        assert_eq!(c, "0x15".parse().unwrap());

        let n: Bignum<26> = nist::NIST_P.widen();
        let r: Bignum<26> = Bignum::ONE << (24 * 64);
        let (a, b, c) = Bignum::xgcd(r, n);
        let a_true = "-0x2638276a12a55f53531790ef47ce2e065b6f8712eb2d4f945df25586114ea80ecb08ea78700f164701481a6ae936a66a760400cbe6523679e06a9f680d52428d3366bae6482534ba96d0a70880a249bc2e8c290779d16ed8e0add541dfc16d056da59bad2334090406f13c6a5af801c7680d84d576d3284792f94170bd15c35b230357d18d13ce51f1a9a948e882aed32aea6378ad8a3ab01d7e2bc45f87ede0ee9f341b39ebf102764140e1890a654da0a71c73887936ee5fb339532a224c26".parse().unwrap();
        let b_true = "0x2638276a12a55f535b4b4378bc8277ecf031263370ec7b7e0acdd4a302f48428dda8ce2446d179b3545d8b4497fb2bb0cdb94451bb92042084d355d080045cd25c77faf2432a1a533486195a5af0c129fe1dc78404679e96fe55bd1332ca3aecf2b229f4cf6cb52b844eed051e87ef3598913c33bf4956fa8ba10dfa570f6f77a011b71e04f5519d306216b0b2d0a6ab80d150971817dc5cdedea9ea69cef646e50da4c795c3bc85c1b6e18de48671bb0e8b93f735dc8cd7ffffffffffffffff".parse().unwrap();
        assert_eq!(a, a_true);
        assert_eq!(b, b_true);
        assert!(c.is_one());
    }

    #[test]
    fn test_inv_mod_bignums() {
        let m: Bignum<1> = "17f".parse().unwrap();
        let a: Bignum<1> = "10f".parse().unwrap();

        let a_inv = a.inv_mod(&m);
        assert_eq!(a_inv, "0x6a".parse().unwrap());

        let n: Bignum<25> = nist::NIST_P.widen();
        let r: Bignum<25> = Bignum::ONE << (24 * 64);

        let n_prime = "0x2638276a12a55f535b4b4378bc8277ecf031263370ec7b7e0acdd4a302f48428dda8ce2446d179b3545d8b4497fb2bb0cdb94451bb92042084d355d080045cd25c77faf2432a1a533486195a5af0c129fe1dc78404679e96fe55bd1332ca3aecf2b229f4cf6cb52b844eed051e87ef3598913c33bf4956fa8ba10dfa570f6f77a011b71e04f5519d306216b0b2d0a6ab80d150971817dc5cdedea9ea69cef646e50da4c795c3bc85c1b6e18de48671bb0e8b93f735dc8cd7ffffffffffffffff".parse().unwrap();

        assert_eq!(n.inv_mod(&r), n_prime);
    }
}
