use crate::rand::Rng32;
use std::cmp::Ordering;
use std::fmt;
use std::num::ParseIntError;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Bignum<const LIMBS: usize> {
    limbs: [u64; LIMBS],
}

pub mod nist_consts {
    use super::Bignum;

    pub const NIST_P: Bignum<48> = Bignum {
        limbs: [
            0xffffffffffffffff,
            0xf1746c08ca237327,
            0x670c354e4abc9804,
            0x9ed529077096966d,
            0x1c62f356208552bb,
            0x83655d23dca3ad96,
            0x69163fa8fd24cf5f,
            0x98da48361c55d39a,
            0xc2007cb8a163bf05,
            0x49286651ece45b3d,
            0xae9f24117c4b1fe6,
            0xee386bfb5a899fa5,
            0xbff5cb6f406b7ed,
            0xf44c42e9a637ed6b,
            0xe485b576625e7ec6,
            0x4fe1356d6d51c245,
            0x302b0a6df25f1437,
            0xef9519b3cd3a431b,
            0x514a08798e3404dd,
            0x20bbea63b139b22,
            0x29024e088a67cc74,
            0xc4c6628b80dc1cd1,
            0xc90fdaa22168c234,
            0xffffffffffffffff,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    };

    pub const NIST_G: Bignum<48> = {
        let mut limbs = [0u64; 48];
        limbs[0] = 2;
        Bignum { limbs }
    };
}

// utility functions
#[allow(dead_code)]
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
            .map(|limb| limb.leading_zeros())
            .take_while(|zeros| *zeros == 64)
            .count();
        let final_limb_leading_ones = self
            .limbs
            .get((LIMBS - one_pos).wrapping_sub(1))
            .unwrap_or(&u64::MAX)
            .leading_zeros();
        one_pos as u32 * 64 + final_limb_leading_ones
    }

    pub fn trailing_zeros(&self) -> u32 {
        let one_pos = self
            .limbs
            .iter()
            .map(|limb| limb.trailing_zeros())
            .take_while(|zeros| *zeros == 64)
            .count();
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
            .map(|limb| limb.leading_ones())
            .take_while(|ones| *ones == 64)
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
            .map(|limb| limb.trailing_ones())
            .take_while(|ones| *ones == 64)
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
        if bit > 64 * LIMBS {
            panic!("attempt to test bit with overflow");
        }

        let limb_idx = bit / 64;
        let bit_idx = bit % 64;

        (self.limbs[limb_idx] >> bit_idx) & 1 == 1
    }

    pub fn random(rng: &mut impl Rng32) -> Self {
        let mut out = Self::default();
        for limb in out.limbs.iter_mut() {
            *limb = u64::from_be_bytes(rng.gen_array());
        }
        out
    }
}

#[allow(dead_code)]
impl<const LIMBS: usize> Bignum<LIMBS> {
    // performs both division and mod and returns the pair (div, mod)
    pub fn divmod(&self, rhs: Self) -> (Self, Self) {
        if rhs.is_zero() {
            panic!("attempt to divide by zero");
        }

        // early exit for simple cases
        if rhs.is_one() {
            return (*self, Bignum::ZERO);
        }

        if rhs > *self {
            return (Bignum::ZERO, *self);
        }

        let mut dividend = *self;
        let mut divisor = rhs;

        // normalise divisor
        let normalising_shift = divisor.leading_zeros() - dividend.leading_zeros();
        divisor <<= normalising_shift;
        debug_assert_eq!(dividend.leading_zeros(), divisor.leading_zeros());

        // initialize quotient and remainder
        let mut quotient = Bignum::ZERO;

        // perform the division
        while dividend >= rhs {
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

    pub fn modexp(self, exponent: Self, prime: Self) -> Self {
        assert!(self.bit_length() <= LIMBS as u32 * 32);
        assert!(prime.bit_length() <= LIMBS as u32 * 32);

        if exponent.is_zero() {
            return Bignum::ONE;
        }

        let mut x = self;
        let mut y = Bignum::ONE;
        for i in 0..(exponent.bit_length() as usize - 1) {
            if exponent.test_bit(i) {
                y = (y * x) % prime;
            }
            x = (x * x) % prime;
        }

        (x * y) % prime
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

        let mut first = true;
        for limb in self.limbs.iter().rev() {
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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let offset = if s.starts_with("0x") { 2 } else { 0 };
        let bytes = &s.as_bytes()[offset..];
        if bytes.len() > LIMBS * 16 {
            return Err(u8::from_str_radix("1000", 10).unwrap_err());
        }

        let mut out = Self::default();
        for (limb, chunk) in out.limbs.iter_mut().zip(bytes.chunks(16).rev()) {
            *limb = u64::from_str_radix(
                std::str::from_utf8(chunk).expect("MMH WHY IS THERE UNICODE IN YOUR NUMBER BOI"),
                16,
            )?;
        }

        Ok(out)
    }
}

impl<const LIMBS: usize> PartialOrd for Bignum<LIMBS> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.limbs
            .iter()
            .zip(other.limbs.iter())
            .rev()
            .filter_map(|(a, b)| (a != b).then(|| a.cmp(b)))
            .next()
            .or(Some(Ordering::Equal))
    }
}

impl<const LIMBS: usize> Ord for Bignum<LIMBS> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

macro_rules! impl_from_for_bignum {
    ($uX:ty) => {
        impl<const LIMBS: usize> From<$uX> for Bignum<LIMBS> {
            fn from(value: $uX) -> Self {
                let mut limbs = [0; LIMBS];
                limbs[0] = value.into();
                Self { limbs }
            }
        }
    };
}

impl_from_for_bignum!(u64);
impl_from_for_bignum!(u32);
impl_from_for_bignum!(u16);
impl_from_for_bignum!(u8);

// we dont have nightly but i can steal from nightly >:)
#[inline]
const fn carrying_add(x: u64, y: u64, carry: bool) -> (u64, bool) {
    let (a, b) = x.overflowing_add(y);
    let (c, d) = a.overflowing_add(carry as u64);
    (c, b != d)
}

#[inline]
const fn borrowing_sub(x: u64, y: u64, carry: bool) -> (u64, bool) {
    let (a, b) = x.overflowing_sub(y);
    let (c, d) = a.overflowing_sub(carry as u64);
    (c, b != d)
}

#[inline]
const fn carrying_mul(x: u64, y: u64, carry: u64) -> (u64, u64) {
    // unchecked is nightly so checked it is
    let wide = x as u128 * y as u128 + carry as u128;
    (wide as u64, (wide >> 64) as u64)
}

impl<const LIMBS: usize> Add for Bignum<LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // implement add in terms of AddAssign
        let mut out = self;
        out += rhs;
        out
    }
}

impl<const LIMBS: usize> AddAssign for Bignum<LIMBS> {
    fn add_assign(&mut self, rhs: Self) {
        let mut carry = false;
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            let (sum, overflow) = carrying_add(*l, *r, carry);
            *l = sum;
            carry = overflow;
        }

        if carry {
            panic!("attempt to add with overflow")
        }
    }
}

impl<const LIMBS: usize> Sub for Bignum<LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        // implement sub in terms of SubAssign
        let mut out = self;
        out -= rhs;
        out
    }
}

impl<const LIMBS: usize> SubAssign for Bignum<LIMBS> {
    fn sub_assign(&mut self, rhs: Self) {
        let mut carry = false;
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            let (sum, overflow) = borrowing_sub(*l, *r, carry);
            *l = sum;
            carry = overflow;
        }

        if carry {
            panic!("attempt to add with overflow")
        }
    }
}

impl<const LIMBS: usize> Mul for Bignum<LIMBS> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut out = Self::default();

        for (i, r) in rhs.limbs.iter().enumerate() {
            let mut carry = 0;
            for (l, o) in self.limbs.iter().zip(out.limbs.iter_mut().skip(i)) {
                let (prod, next_carry) = carrying_mul(*r, *l, carry);
                let (new_limb, add_carry) = o.overflowing_add(prod);
                carry = next_carry + u64::from(add_carry);
                *o = new_limb;
            }

            if carry != 0 {
                panic!("attempt to mul with overflow");
            }
        }

        out
    }
}

impl<const LIMBS: usize> MulAssign for Bignum<LIMBS> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<const LIMBS: usize> Rem for Bignum<LIMBS> {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self::Output {
        self.divmod(rhs).1
    }
}

impl<const LIMBS: usize> RemAssign for Bignum<LIMBS> {
    fn rem_assign(&mut self, rhs: Self) {
        *self = *self % rhs;
    }
}

impl<const LIMBS: usize> Div for Bignum<LIMBS> {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        self.divmod(rhs).0
    }
}

impl<const LIMBS: usize> DivAssign for Bignum<LIMBS> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<const LIMBS: usize> Shr<u32> for Bignum<LIMBS> {
    type Output = Self;

    fn shr(self, rhs: u32) -> Self::Output {
        if rhs as usize > LIMBS * 64 {
            panic!("attempt to shift right with overflow");
        }

        let mut out = Self::default();

        // we have 64 * LIMBS total bits
        // a shift of N bits moves the top 64 * LIMBS - N bits to the lowest bits
        // meaning the lowest eventual limb is
        let bottom_limb = rhs as usize / 64;
        let limb_split_pos = rhs % 64;

        // chain on the final limb so that we correctly set the last limb of the output
        let last_pair = &[self.limbs[LIMBS - 1], 0][..];
        let limb_pairs = self
            .limbs
            .windows(2)
            .skip(bottom_limb)
            .chain(std::iter::once(last_pair));
        for (o, limb_pair) in out.limbs.iter_mut().zip(limb_pairs) {
            let upper = limb_pair[1].checked_shl(64 - limb_split_pos).unwrap_or(0);
            *o = (limb_pair[0] >> limb_split_pos) | upper;
        }

        out
    }
}

impl<const LIMBS: usize> ShrAssign<u32> for Bignum<LIMBS> {
    fn shr_assign(&mut self, rhs: u32) {
        *self = *self >> rhs;
    }
}

impl<const LIMBS: usize> Shl<u32> for Bignum<LIMBS> {
    type Output = Self;

    fn shl(self, rhs: u32) -> Self::Output {
        if rhs as usize > LIMBS * 64 {
            panic!("attempt to shift left with overflow");
        }

        let mut out = Self::default();

        // we have 64 * LIMBS total bits
        // a shift of N bits moves the top 64 * LIMBS - N bits to the lowest bits
        // meaning the lowest eventual limb is
        let bottom_limb = rhs as usize / 64;
        let limb_split_pos = rhs % 64;

        // chain on the final limb so that we correctly set the last limb of the output
        let first_pair = &[0, self.limbs[0]][..];
        let limb_pairs = std::iter::once(first_pair).chain(self.limbs.windows(2));
        let out_limbs = out.limbs.iter_mut().skip(bottom_limb);
        for (o, limb_pair) in out_limbs.zip(limb_pairs) {
            let lower = limb_pair[0].checked_shr(64 - limb_split_pos).unwrap_or(0);
            *o = lower | (limb_pair[1] << limb_split_pos);
        }

        out
    }
}

impl<const LIMBS: usize> ShlAssign<u32> for Bignum<LIMBS> {
    fn shl_assign(&mut self, rhs: u32) {
        *self = *self << rhs;
    }
}

impl<const LIMBS: usize> BitAnd for Bignum<LIMBS> {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out &= rhs;
        out
    }
}

impl<const LIMBS: usize> BitAndAssign for Bignum<LIMBS> {
    fn bitand_assign(&mut self, rhs: Self) {
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs) {
            *l &= r;
        }
    }
}

impl<const LIMBS: usize> BitOr for Bignum<LIMBS> {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out |= rhs;
        out
    }
}

impl<const LIMBS: usize> BitOrAssign for Bignum<LIMBS> {
    fn bitor_assign(&mut self, rhs: Self) {
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs) {
            *l |= r;
        }
    }
}

impl<const LIMBS: usize> BitXor for Bignum<LIMBS> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out ^= rhs;
        out
    }
}

impl<const LIMBS: usize> BitXorAssign for Bignum<LIMBS> {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs) {
            *l ^= r;
        }
    }
}

impl<const LIMBS: usize> Not for Bignum<LIMBS> {
    type Output = Self;
    fn not(self) -> Self::Output {
        let mut out = self;
        for o in out.limbs.iter_mut() {
            *o = !*o;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::bignum::Bignum;

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
        let p1: Bignum<48> = "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".parse().unwrap();
        let p2: Bignum<48> = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".parse().unwrap();
        assert_eq!(p1, super::nist_consts::NIST_P);
        assert_eq!(p2, super::nist_consts::NIST_P);
    }

    #[test]
    fn test_cmp_bignums() {
        let a: Bignum<10> = 0xFFFF_u16.into();
        assert!(a > Bignum::MIN && a < Bignum::MAX);

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
        let one = 1u8.into();
        assert!(a > one && one < a);
    }

    #[test]
    fn test_add_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();

        assert_eq!(a + b, 11u8.into());

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = 1u8.into();
        let c = a + b;
        assert_eq!(c.limbs[1], 1);
        assert_eq!(c.limbs[0], 0);

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        let c = a + b;
        assert_eq!(c.limbs[1], 1);
        assert_eq!(c.limbs[0], u64::MAX - 1);
    }

    #[test]
    fn test_add_assign_bignums() {
        let mut a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        a += b;
        assert_eq!(a, 11u8.into());

        let mut a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = 1u8.into();
        a += b;
        assert_eq!(a.limbs[1], 1);
        assert_eq!(a.limbs[0], 0);

        let mut a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        a += b;
        assert_eq!(a.limbs[1], 1);
        assert_eq!(a.limbs[0], u64::MAX - 1);
    }

    #[test]
    fn test_sub_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        assert_eq!(b - a, 1u8.into());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 1u8.into();
        let c = a - b;
        assert_eq!(c, u64::MAX.into());

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        let c = a - b;
        assert_eq!(c, 0u8.into());
    }

    #[test]
    fn test_sub_assign_bignums() {
        let a: Bignum<10> = 5u8.into();
        let mut b: Bignum<10> = 6u8.into();
        b -= a;
        assert_eq!(b, 1u8.into());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 1u8.into();
        a -= b;
        assert_eq!(a, u64::MAX.into());

        let mut a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        a -= b;
        assert_eq!(a, 0u8.into());

        let mut a: Bignum<10> = Bignum {
            limbs: [u64::MAX / 2, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = u64::MAX.into();
        let c: Bignum<10> = Bignum {
            limbs: [1 << 63, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        a -= b;
        assert_eq!(a, c);
    }

    #[test]
    fn test_mul_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        assert_eq!(b * a, 30u8.into());
        // assert!(a.limbs[0] == 123);

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 10u8.into();
        assert_eq!(
            a * b,
            Bignum {
                limbs: [0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        assert_eq!(
            a * b,
            Bignum {
                limbs: [1, u64::MAX - 1, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );

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
        assert_eq!(
            a * a,
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
    }

    #[test]
    fn test_mul_assign_bignums() {
        let mut a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        a *= b;
        assert_eq!(a, 30u8.into());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 10u8.into();
        a *= b;
        assert_eq!(
            a,
            Bignum {
                limbs: [0, 10, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );

        let mut a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        a *= b;
        assert_eq!(
            a,
            Bignum {
                limbs: [1, u64::MAX - 1, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );

        let mut a = Bignum {
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
        a *= a;
        assert_eq!(
            a,
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
    }

    #[test]
    fn test_divmod_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        assert_eq!(a.divmod(b), (0u8.into(), a));

        let a: Bignum<10> = 1234u16.into();
        let b: Bignum<10> = 56u8.into();
        assert_eq!(a.divmod(b), (22u8.into(), 2u8.into()));

        let a: Bignum<10> = 12345_u32.into();
        let b: Bignum<10> = 10u8.into();
        assert_eq!(a.divmod(b), (1234u16.into(), 5u8.into()));

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        assert_eq!(a.divmod(b), (1u8.into(), Bignum::ZERO));

        let a: Bignum<10> = Bignum {
            limbs: [u64::MAX, u64::MAX, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = u64::MAX.into();
        assert_eq!(
            a.divmod(b),
            (
                Bignum {
                    limbs: [1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                },
                Bignum::ZERO
            )
        );

        let a: Bignum<10> = Bignum::MAX;
        let b: Bignum<10> = u64::MAX.into();
        assert_eq!(a.divmod(b), (Bignum { limbs: [1; 10] }, Bignum::ZERO));
    }

    #[test]
    fn test_div_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        assert!((b / a).is_one());
        assert!((a / b).is_zero());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 10u8.into();
        assert_eq!(a / b, 0x1999999999999999_u64.into());

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        assert!((a / b).is_one());

        let a = Bignum {
            limbs: [
                0x6bfd532eb947c673,
                0x8e98c292493d61d7,
                0xd60f263b7c6df781,
                0xfb386a2a8e81667d,
                0xa06b2d52d4912959,
                0xf0e1e5d6919e7cc7,
                0xcdacea38cfbab56f,
                0x7e738acc18d8deb5,
                0x286b1e683604e595,
                0xabf022ad49921511,
            ],
        };
        let b = Bignum {
            limbs: [
                0x19fd8394b7d3132a,
                0x422fadeab46ddcb0,
                0x30d1cb341a4ac45f,
                0xeec004de9a047a3b,
                0x176c473a8fd,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        let c = Bignum {
            limbs: [
                0x989bf5494e86059f,
                0x289535aece53ee9f,
                0xeb9422228969c825,
                0xc84a3ea7ed6cf346,
                0xb43e1bc51198548a,
                0x7572ff,
                0,
                0,
                0,
                0,
            ],
        };
        assert_eq!(a / b, c);
    }

    #[test]
    fn test_div_assign_bignums() {
        let mut a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        a /= b;
        assert!((a / b).is_zero());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 10u8.into();
        a /= b;
        assert_eq!(a, 0x1999999999999999_u64.into());

        let mut a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        a /= b;
        assert!(a.is_one());

        let mut a = Bignum {
            limbs: [
                0x6bfd532eb947c673,
                0x8e98c292493d61d7,
                0xd60f263b7c6df781,
                0xfb386a2a8e81667d,
                0xa06b2d52d4912959,
                0xf0e1e5d6919e7cc7,
                0xcdacea38cfbab56f,
                0x7e738acc18d8deb5,
                0x286b1e683604e595,
                0xabf022ad49921511,
            ],
        };
        let b = Bignum {
            limbs: [
                0x19fd8394b7d3132a,
                0x422fadeab46ddcb0,
                0x30d1cb341a4ac45f,
                0xeec004de9a047a3b,
                0x176c473a8fd,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        let c = Bignum {
            limbs: [
                0x989bf5494e86059f,
                0x289535aece53ee9f,
                0xeb9422228969c825,
                0xc84a3ea7ed6cf346,
                0xb43e1bc51198548a,
                0x7572ff,
                0,
                0,
                0,
                0,
            ],
        };
        a /= b;
        assert_eq!(a, c);
    }

    #[test]
    fn test_rem_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        assert_eq!(a % b, a);
        assert!((b % a).is_one());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 10u8.into();
        assert_eq!(a % b, 6_u8.into());

        let a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        assert!((a % b).is_zero());

        let a = Bignum {
            limbs: [
                0x6bfd532eb947c673,
                0x8e98c292493d61d7,
                0xd60f263b7c6df781,
                0xfb386a2a8e81667d,
                0xa06b2d52d4912959,
                0xf0e1e5d6919e7cc7,
                0xcdacea38cfbab56f,
                0x7e738acc18d8deb5,
                0x286b1e683604e595,
                0xabf022ad49921511,
            ],
        };
        let b = Bignum {
            limbs: [
                0x19fd8394b7d3132a,
                0x422fadeab46ddcb0,
                0x30d1cb341a4ac45f,
                0xeec004de9a047a3b,
                0x176c473a8fd,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        let c = Bignum {
            limbs: [
                0x2d2680ec99d30d5d,
                0xad5e5c257ca89a92,
                0x3019d5547be64a46,
                0xa40a6a063ebf3954,
                0xf1f3f1e1fc,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        assert_eq!(a % b, c);
    }

    #[test]
    fn test_rem_assign_bignums() {
        let a: Bignum<10> = 5u8.into();
        let mut b: Bignum<10> = 6u8.into();
        b %= a;
        assert!(b.is_one());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = 10u8.into();
        a %= b;
        assert_eq!(a, 6_u8.into());

        let mut a: Bignum<10> = u64::MAX.into();
        let b: Bignum<10> = u64::MAX.into();
        a %= b;
        assert!(a.is_zero());

        let mut a = Bignum {
            limbs: [
                0x6bfd532eb947c673,
                0x8e98c292493d61d7,
                0xd60f263b7c6df781,
                0xfb386a2a8e81667d,
                0xa06b2d52d4912959,
                0xf0e1e5d6919e7cc7,
                0xcdacea38cfbab56f,
                0x7e738acc18d8deb5,
                0x286b1e683604e595,
                0xabf022ad49921511,
            ],
        };
        let b = Bignum {
            limbs: [
                0x19fd8394b7d3132a,
                0x422fadeab46ddcb0,
                0x30d1cb341a4ac45f,
                0xeec004de9a047a3b,
                0x176c473a8fd,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        let c = Bignum {
            limbs: [
                0x2d2680ec99d30d5d,
                0xad5e5c257ca89a92,
                0x3019d5547be64a46,
                0xa40a6a063ebf3954,
                0xf1f3f1e1fc,
                0,
                0,
                0,
                0,
                0,
            ],
        };
        a %= b;
        assert_eq!(a, c);
    }

    #[test]
    fn test_modexp_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        let p = 7u8.into();
        assert_eq!(a.modexp(b, p), 1u8.into());

        let a: Bignum<10> = 1234u16.into();
        let b: Bignum<10> = 56u8.into();
        let p = 63097u16.into();
        assert_eq!(a.modexp(b, p), 19484u16.into());

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
        let b = Bignum {
            limbs: [
                0xe8772512ce1f7b9f,
                0x451aa7d52bf5c78d,
                0x642d57d46c59d77f,
                0x2837cdd88dda035,
                0x14051e1547177b5c,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
            ],
        };
        let p = Bignum {
            limbs: [
                0x603cefe390418a2b,
                0xed8ee51b4a3b8ee2,
                0x2ec9a9dc5c9d8cfc,
                0x216145bd7def3632,
                0xfd26188815dbff75,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
            ],
        };

        assert_eq!(a.modexp(Bignum::ZERO, p), Bignum::ONE);
        assert_eq!(
            a.modexp(b, p),
            Bignum {
                limbs: [
                    0x9b8e80cf15097ec8,
                    0xb65ab0282cdd9221,
                    0x2336422285e470fd,
                    0xc23f88da48ef28c5,
                    0x924f5dadc7c825ac,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                    0x0,
                ],
            }
        );
    }

    #[test]
    fn test_shr_bignums() {
        let a: Bignum<10> = u64::MAX.into();
        assert_eq!(a >> 30, (u64::MAX >> 30).into());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(a >> 1, (1_u64 << 63).into());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(a >> 64, 1u8.into());

        let a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        assert_eq!(
            a >> 7,
            Bignum {
                limbs: [
                    u64::MAX << (64 - 7),
                    u64::MAX,
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                    u64::MAX << (64 - 7),
                    u64::MAX >> 7
                ],
            }
        );

        let a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        assert_eq!(
            a >> 135,
            Bignum {
                limbs: [
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                    u64::MAX << (64 - 7),
                    u64::MAX >> 7,
                    0,
                    0
                ],
            }
        );
    }

    #[test]
    fn test_shr_assign_bignums() {
        let mut a: Bignum<10> = u64::MAX.into();
        a >>= 30;
        assert_eq!(a, (u64::MAX >> 30).into());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        a >>= 1;
        assert_eq!(a, (1_u64 << 63).into());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        a >>= 64;
        assert_eq!(a, 1u8.into());

        let mut a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        a >>= 7;
        assert_eq!(
            a,
            Bignum {
                limbs: [
                    u64::MAX << (64 - 7),
                    u64::MAX,
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                    u64::MAX << (64 - 7),
                    u64::MAX >> 7
                ],
            }
        );

        let mut a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        a >>= 135;
        assert_eq!(
            a,
            Bignum {
                limbs: [
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                    u64::MAX << (64 - 7),
                    u64::MAX >> 7,
                    0,
                    0
                ],
            }
        );
    }

    #[test]
    fn test_shl_bignums() {
        let a: Bignum<10> = 1_u8.into();
        assert_eq!(a << 30, (1_u32 << 30).into());

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            a << 10,
            Bignum {
                limbs: [0, 1 << 10, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            a << 128,
            Bignum {
                limbs: [0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            }
        );

        let a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        assert_eq!(
            a << 64 - 7,
            Bignum {
                limbs: [
                    0,
                    u64::MAX << (64 - 7),
                    u64::MAX,
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                    u64::MAX << (64 - 7)
                ],
            }
        );

        let a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        assert_eq!(
            a << 128 - 7,
            Bignum {
                limbs: [
                    0,
                    0,
                    u64::MAX << (64 - 7),
                    u64::MAX,
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                ],
            }
        );
    }

    #[test]
    fn test_shl_assign_bignums() {
        let mut a: Bignum<10> = 1_u8.into();
        a <<= 30;
        assert_eq!(a, (1_u32 << 30).into());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        a <<= 10;
        assert_eq!(
            a,
            Bignum {
                limbs: [0, 1 << 10, 0, 0, 0, 0, 0, 0, 0, 0],
            }
        );

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        a <<= 128;
        assert_eq!(
            a,
            Bignum {
                limbs: [0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            }
        );

        let mut a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        a <<= 64 - 7;
        assert_eq!(
            a,
            Bignum {
                limbs: [
                    0,
                    u64::MAX << (64 - 7),
                    u64::MAX,
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                    u64::MAX << (64 - 7)
                ],
            }
        );

        let mut a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        a <<= 128 - 7;
        assert_eq!(
            a,
            Bignum {
                limbs: [
                    0,
                    0,
                    u64::MAX << (64 - 7),
                    u64::MAX,
                    u64::MAX >> 7,
                    0,
                    0,
                    0,
                    0,
                    1,
                ],
            }
        );
    }

    #[test]
    fn test_bitand_assign_bignums() {
        let mut a: Bignum<10> = 0xFFFF_u16.into();
        let b: Bignum<10> = 0xFFFF000_u32.into();
        a &= b;
        assert_eq!(a, 0xF000_u32.into());

        let mut a: Bignum<10> = Bignum {
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
        let b: Bignum<10> = Bignum {
            limbs: [
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
            ],
        };
        a &= b;
        assert_eq!(a, Bignum::ZERO);
    }

    #[test]
    fn test_bitand_bignums() {
        let a: Bignum<10> = 0xFFFF_u16.into();
        let b: Bignum<10> = 0xFFFF000_u32.into();
        assert_eq!(a & b, 0xF000_u32.into());

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
        let b: Bignum<10> = Bignum {
            limbs: [
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
            ],
        };
        assert_eq!(a & b, Bignum::ZERO);
    }

    #[test]
    fn test_bitor_assign_bignums() {
        let mut a: Bignum<10> = 0xFFFF_u16.into();
        let b: Bignum<10> = 0xFFFF000_u32.into();
        a |= b;
        assert_eq!(a, 0xFFFFFFF_u32.into());

        let mut a: Bignum<10> = Bignum {
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
        let b: Bignum<10> = Bignum {
            limbs: [
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
            ],
        };
        a |= b;
        assert_eq!(a, Bignum::MAX);
    }

    #[test]
    fn test_bitor_bignums() {
        let a: Bignum<10> = 0xFFFF_u16.into();
        let b: Bignum<10> = 0xFFFF000_u32.into();
        assert_eq!(a | b, 0xFFFFFFF_u32.into());

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
        let b: Bignum<10> = Bignum {
            limbs: [
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
            ],
        };
        assert_eq!(a | b, Bignum::MAX);
    }

    #[test]
    fn test_bitxor_assign_bignums() {
        let mut a: Bignum<10> = 0xFFFF_u16.into();
        let b: Bignum<10> = 0xFFFF000_u32.into();
        a ^= b;
        assert_eq!(a, 0xFFF0FFF_u32.into());

        let mut a: Bignum<10> = Bignum {
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
        let b: Bignum<10> = Bignum {
            limbs: [
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
            ],
        };
        a ^= b;
        assert_eq!(a, Bignum::MAX);
    }

    #[test]
    fn test_bitxor_bignums() {
        let a: Bignum<10> = 0xFFFF_u16.into();
        let b: Bignum<10> = 0xFFFF000_u32.into();
        assert_eq!(a ^ b, 0xFFF0FFF_u32.into());

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
        let b: Bignum<10> = Bignum {
            limbs: [
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
            ],
        };
        assert_eq!(a ^ b, Bignum::MAX);
    }

    #[test]
    fn test_not_bignums() {
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
        let b: Bignum<10> = Bignum {
            limbs: [
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
                u64::MAX,
                0,
            ],
        };
        assert_eq!(!a, b);
        assert_eq!(!Bignum::<10>::ZERO, Bignum::<10>::MAX);
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
}
