#![allow(clippy::clone_on_copy)]

//! THE BIBLE: https://cacr.uwaterloo.ca/hac/about/chap14.pdf

use crate::monty::Monty;
use crate::rand::Rng32;
use std::cmp::Ordering;
use std::fmt;
use std::num::ParseIntError;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};
use std::str::FromStr;

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

// utility functions
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

    pub fn random(mut rng: impl Rng32) -> Self {
        let mut out = Self::ZERO;
        for limb in out.limbs.iter_mut() {
            *limb = u64::from_be_bytes(rng.gen_array());
        }
        out
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

    pub fn modexp(self, exponent: Self, prime: Self) -> Self {
        debug_assert!(self.bit_length() <= LIMBS as u32 * 32);
        debug_assert!(prime.bit_length() <= LIMBS as u32 * 32);

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

impl<const LIMBS: usize> Bignum<LIMBS> {
    pub(super) fn add_with_overflow(&mut self, rhs: &Self) -> bool {
        let mut carry = false;
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            let (sum, overflow) = carrying_add(*l, *r, carry);
            *l = sum;
            carry = overflow;
        }
        carry
    }

    fn sub_with_overflow(&mut self, rhs: &Self) -> bool {
        let mut carry = false;
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            let (sum, overflow) = borrowing_sub(*l, *r, carry);
            *l = sum;
            carry = overflow;
        }
        carry
    }

    fn negate(&mut self) {
        let mut carry = true;
        for l in self.limbs.iter_mut() {
            let (sum, overflow) = carrying_add(!*l, 0, carry);
            *l = sum;
            carry = overflow;
        }
    }

    fn mul_with_overflow(&mut self, rhs: &Self) -> bool {
        let mut out = Self::ZERO.clone();
        let mut overflow = false;

        for (i, r) in rhs.limbs.iter().enumerate() {
            let mut carry = 0;
            for (l, o) in self.limbs.iter().zip(out.limbs.iter_mut().skip(i)) {
                let (prod, next_carry) = carrying_mul(*r, *l, carry);
                let (new_limb, add_carry) = o.overflowing_add(prod);
                carry = next_carry + u64::from(add_carry);
                *o = new_limb;
            }

            overflow |= carry != 0;
        }

        *self = out;
        overflow
    }

    fn shr_with_overflow(&mut self, rhs: u32) -> bool {
        if rhs as usize > LIMBS * 64 {
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
            self.limbs.copy_within(bottom_limb..LIMBS, 0)
        } else {
            for i in 0..(LIMBS - bottom_limb - 1) {
                let upper = self.limbs[bottom_limb + i + 1] << (64 - limb_split_pos);
                let lower = self.limbs[bottom_limb + i] >> limb_split_pos;
                self.limbs[i] = upper | lower;
            }

            self.limbs[LIMBS - bottom_limb - 1] = self.limbs[LIMBS - 1] >> limb_split_pos;
        }

        for i in 0..bottom_limb {
            self.limbs[LIMBS - i - 1] = 0;
        }

        false
    }

    fn shl_with_overflow(&mut self, rhs: u32) -> bool {
        if rhs as usize > LIMBS * 64 {
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
            self.limbs.copy_within(0..LIMBS - bottom_limb, bottom_limb)
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

    fn arithmetic_shr_with_overflow(&mut self, rhs: u32) -> bool {
        if rhs as usize > LIMBS * 64 {
            *self = Self::ZERO;
            return true;
        }

        // first determine the fill limb
        let fill_limb = if (self.limbs[LIMBS - 1] >> 63) == 0 {
            u64::MIN
        } else {
            u64::MAX
        };

        // we have 64 * LIMBS total bits
        // a shift of N bits moves the top 64 * LIMBS - N bits to the lowest bits
        // meaning the lowest eventual limb is
        let bottom_limb = rhs as usize / 64;
        let limb_split_pos = rhs % 64;

        // we can optimise for word aligned shifts
        if limb_split_pos == 0 {
            self.limbs.copy_within(bottom_limb..LIMBS, 0)
        } else {
            for i in 0..(LIMBS - bottom_limb - 1) {
                let upper = self.limbs[bottom_limb + i + 1] << (64 - limb_split_pos);
                let lower = self.limbs[bottom_limb + i] >> limb_split_pos;
                self.limbs[i] = upper | lower;
            }

            let upper = fill_limb << (64 - limb_split_pos);
            let lower = self.limbs[LIMBS - 1] >> limb_split_pos;
            self.limbs[LIMBS - bottom_limb - 1] = upper | lower;
        }

        for i in 0..bottom_limb {
            self.limbs[LIMBS - i - 1] = fill_limb;
        }

        false
    }

    fn bitwise_and(&mut self, rhs: &Self) {
        for (o, i) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            *o &= *i;
        }
    }

    fn bitwise_or(&mut self, rhs: &Self) {
        for (o, i) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            *o |= *i;
        }
    }

    fn bitwise_xor(&mut self, rhs: &Self) {
        for (o, i) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            *o ^= *i;
        }
    }

    fn quotient(&mut self, rhs: &Self) {
        *self = self.divmod(rhs).0;
    }

    fn remainder(&mut self, rhs: &Self) {
        *self = self.divmod(rhs).1;
    }

    fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    fn is_odd(&self) -> bool {
        !self.is_even()
    }

    fn is_negative(&self) -> bool {
        (self.limbs[LIMBS - 1] >> 63) == 1
    }

    fn widen<const OUT_LIMBS: usize>(&self) -> Bignum<OUT_LIMBS> {
        let mut out: Bignum<OUT_LIMBS> = Bignum::ZERO;
        out.limbs[..LIMBS].copy_from_slice(&self.limbs);
        out
    }

    fn narrow<const OUT_LIMBS: usize>(&self) -> Bignum<OUT_LIMBS> {
        let mut out: Bignum<OUT_LIMBS> = Bignum::ZERO;
        out.limbs.copy_from_slice(&self.limbs[..OUT_LIMBS]);
        out
    }

    fn split<const LEFT_LIMBS: usize, const RIGHT_LIMBS: usize>(
        &self,
    ) -> (Bignum<LEFT_LIMBS>, Bignum<RIGHT_LIMBS>) {
        let mut left: Bignum<LEFT_LIMBS> = Bignum::ZERO;
        let mut right: Bignum<RIGHT_LIMBS> = Bignum::ZERO;
        left.limbs.copy_from_slice(&self.limbs[..LEFT_LIMBS]);
        right.limbs.copy_from_slice(&self.limbs[LEFT_LIMBS..]);
        (left, right)
    }

    #[allow(non_snake_case)]
    fn xgcd(x: &Self, y: &Self) -> (Self, Self, Self) {
        debug_assert!(x.is_odd() || y.is_odd());

        let mut u = *x;
        let mut v = *y;
        let mut A = Self::ONE;
        let mut B = Self::ZERO;
        let mut C = Self::ZERO;
        let mut D = Self::ONE;

        while !u.is_zero() {
            while u.is_even() {
                u >>= 1;

                if A.is_odd() || B.is_odd() {
                    A.add_with_overflow(y);
                    B.sub_with_overflow(x);
                }

                A.arithmetic_shr_with_overflow(1);
                B.arithmetic_shr_with_overflow(1);
            }

            while v.is_even() {
                v >>= 1;

                if C.is_odd() || D.is_odd() {
                    C.add_with_overflow(y);
                    D.sub_with_overflow(x);
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

        (C, D, v)
    }

    fn bezouts_coeffs(a: &Self, b: &Self) -> (Self, Self) {
        let (mut s, mut old_s) = (Self::ZERO, Self::ONE);
        let (mut r, mut old_r) = (b.clone(), a.clone());

        while !r.is_zero() {
            let mut suband = old_r;
            suband.div_assign(&r);
            suband.mul_assign(&r);

            old_r.sub_with_overflow(&suband);
            std::mem::swap(&mut r, &mut old_r);
            // (old_r, r) = (r, old_r - quotient * r);

            old_s.sub_with_overflow(&suband);
            std::mem::swap(&mut s, &mut old_s);
            // (old_s, s) = (s, old_s - quotient * s);
        }

        let mut bezout_t = Self::ZERO;

        if !b.is_zero() {
            eprintln!("{old_r} - {old_s} * {a}");
            let mut suband = old_s;
            suband.mul_assign(a);
            bezout_t.sub_with_overflow(&suband);
        };

        eprintln!("s = {s}");
        eprintln!("old_s = {old_s}");
        eprintln!("r = {r}");
        eprintln!("old_r = {old_r}");

        (old_s, bezout_t)
    }

    /// Converts to a montgomery form bigint with modulus r
    ///
    /// - assumes N to be 2^(LIMBS-2)
    fn to_monty(r: &Self) -> Monty<LIMBS> {
        // to do montgomery form operations we need 2 limbs of working space
        debug_assert!(r.limbs[LIMBS - 1] == 0 && r.limbs[LIMBS - 2] == 0);

        let mut n = Self::ZERO;
        n.limbs[LIMBS - 2] = 1;

        dbg!(Self::bezouts_coeffs(r, &n));
        todo!()
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
        for (limb, chunk) in out.limbs.iter_mut().zip(bytes.chunks(16).rev()) {
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

impl<const LIMBS: usize> PartialOrd for Bignum<LIMBS> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const LIMBS: usize> Ord for Bignum<LIMBS> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.limbs
            .iter()
            .zip(other.limbs.iter())
            .rev()
            .map(|(a, b)| a.cmp(b))
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    }
}

impl<const LIMBS: usize> Neg for Bignum<LIMBS> {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        self.negate();
        self
    }
}

impl<const LIMBS: usize> Neg for &Bignum<LIMBS> {
    type Output = Bignum<LIMBS>;
    fn neg(self) -> Self::Output {
        let mut out = self.clone();
        out.negate();
        out
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

macro_rules! bignum_arith_impls {
    ($rhs:ty, allow_rhs_ref, $trait:ident, $op:ident, $trait_assign:ident, $op_assign:ident, $method:ident, $overflow_message:literal) => {
        impl<const LIMBS: usize> $trait<$rhs> for Bignum<LIMBS> {
            type Output = Self;

            fn $op(self, rhs: $rhs) -> Self::Output {
                let mut out = self.clone();
                let overflow = out.$method(&rhs);
                debug_assert!(!overflow, $overflow_message);
                out
            }
        }

        impl<const LIMBS: usize> $trait<&$rhs> for Bignum<LIMBS> {
            type Output = Self;

            fn $op(self, rhs: &$rhs) -> Self::Output {
                let mut out = self.clone();
                let overflow = out.$method(rhs);
                debug_assert!(!overflow, $overflow_message);
                out
            }
        }

        impl<const LIMBS: usize> $trait<$rhs> for &Bignum<LIMBS> {
            type Output = Bignum<LIMBS>;

            fn $op(self, rhs: $rhs) -> Self::Output {
                let mut out = self.clone();
                let overflow = out.$method(&rhs);
                debug_assert!(!overflow, $overflow_message);
                out
            }
        }

        impl<const LIMBS: usize> $trait<&$rhs> for &Bignum<LIMBS> {
            type Output = Bignum<LIMBS>;

            fn $op(self, rhs: &$rhs) -> Self::Output {
                let mut out = self.clone();
                let overflow = out.$method(rhs);
                debug_assert!(!overflow, $overflow_message);
                out
            }
        }

        impl<const LIMBS: usize> $trait_assign<$rhs> for Bignum<LIMBS> {
            fn $op_assign(&mut self, rhs: $rhs) {
                let overflow = self.$method(&rhs);
                debug_assert!(!overflow, $overflow_message);
            }
        }

        impl<const LIMBS: usize> $trait_assign<&$rhs> for Bignum<LIMBS> {
            fn $op_assign(&mut self, rhs: &$rhs) {
                let overflow = self.$method(rhs);
                debug_assert!(!overflow, $overflow_message);
            }
        }
    };

    ($rhs:ty, allow_rhs_ref, $trait:ident, $op:ident, $trait_assign:ident, $op_assign:ident, $method:ident, no_overflow) => {
        impl<const LIMBS: usize> $trait<$rhs> for Bignum<LIMBS> {
            type Output = Self;

            fn $op(self, rhs: $rhs) -> Self::Output {
                let mut out = self.clone();
                out.$method(&rhs);
                out
            }
        }

        impl<const LIMBS: usize> $trait<&$rhs> for Bignum<LIMBS> {
            type Output = Self;

            fn $op(self, rhs: &$rhs) -> Self::Output {
                let mut out = self.clone();
                out.$method(rhs);
                out
            }
        }

        impl<const LIMBS: usize> $trait<$rhs> for &Bignum<LIMBS> {
            type Output = Bignum<LIMBS>;

            fn $op(self, rhs: $rhs) -> Self::Output {
                let mut out = self.clone();
                out.$method(&rhs);
                out
            }
        }

        impl<const LIMBS: usize> $trait<&$rhs> for &Bignum<LIMBS> {
            type Output = Bignum<LIMBS>;

            fn $op(self, rhs: &$rhs) -> Self::Output {
                let mut out = self.clone();
                out.$method(rhs);
                out
            }
        }

        impl<const LIMBS: usize> $trait_assign<$rhs> for Bignum<LIMBS> {
            fn $op_assign(&mut self, rhs: $rhs) {
                self.$method(&rhs)
            }
        }

        impl<const LIMBS: usize> $trait_assign<&$rhs> for Bignum<LIMBS> {
            fn $op_assign(&mut self, rhs: &$rhs) {
                self.$method(rhs)
            }
        }
    };

    ($rhs:ty, no_rhs_ref, $trait:ident, $op:ident, $trait_assign:ident, $op_assign:ident, $method:ident, $overflow_message:literal) => {
        impl<const LIMBS: usize> $trait<$rhs> for Bignum<LIMBS> {
            type Output = Self;

            fn $op(self, rhs: $rhs) -> Self::Output {
                let mut out = self.clone();
                let overflow = out.$method(rhs);
                debug_assert!(!overflow, $overflow_message);
                out
            }
        }

        impl<const LIMBS: usize> $trait<$rhs> for &Bignum<LIMBS> {
            type Output = Bignum<LIMBS>;

            fn $op(self, rhs: $rhs) -> Self::Output {
                let mut out = self.clone();
                let overflow = out.$method(rhs);
                debug_assert!(!overflow, $overflow_message);
                out
            }
        }

        impl<const LIMBS: usize> $trait_assign<$rhs> for Bignum<LIMBS> {
            fn $op_assign(&mut self, rhs: $rhs) {
                let overflow = self.$method(rhs);
                debug_assert!(!overflow, $overflow_message);
            }
        }
    };
}

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    Add,
    add,
    AddAssign,
    add_assign,
    add_with_overflow,
    "attempt to add with overflow"
);

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    Sub,
    sub,
    SubAssign,
    sub_assign,
    sub_with_overflow,
    "attempt to subtract with overflow"
);

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    Mul,
    mul,
    MulAssign,
    mul_assign,
    mul_with_overflow,
    "attempt to multiply with overflow"
);

bignum_arith_impls!(
    u32,
    no_rhs_ref,
    Shr,
    shr,
    ShrAssign,
    shr_assign,
    shr_with_overflow,
    "attempt to shift-right with overflow"
);

bignum_arith_impls!(
    u32,
    no_rhs_ref,
    Shl,
    shl,
    ShlAssign,
    shl_assign,
    shl_with_overflow,
    "attempt to shift-left with overflow"
);

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    BitAnd,
    bitand,
    BitAndAssign,
    bitand_assign,
    bitwise_and,
    no_overflow
);

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    BitOr,
    bitor,
    BitOrAssign,
    bitor_assign,
    bitwise_or,
    no_overflow
);

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    BitXor,
    bitxor,
    BitXorAssign,
    bitxor_assign,
    bitwise_xor,
    no_overflow
);

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    Rem,
    rem,
    RemAssign,
    rem_assign,
    remainder,
    no_overflow
);

bignum_arith_impls!(
    Bignum<LIMBS>,
    allow_rhs_ref,
    Div,
    div,
    DivAssign,
    div_assign,
    quotient,
    no_overflow
);

#[cfg(test)]
mod tests {
    use crate::bignum::{nist_consts, Bignum};

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
        assert!(a > one);
        assert!(one < a);
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
    fn test_neg_bignums() {
        assert_eq!(-Bignum::<10>::ZERO, Bignum::<10>::ZERO);
        assert_eq!(-Bignum::<10>::MAX, Bignum::<10>::ONE);
        assert_eq!(-Bignum::<10>::ONE, Bignum::<10>::MAX);

        let a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b: Bignum<10> = Bignum {
            limbs: [
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ],
        };
        assert_eq!(-a, b);
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
        for _ in 0..1000 {
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
    fn test_arithmetic_shr_with_overflow_bignums() {
        let mut a: Bignum<10> = u64::MAX.into();
        a.arithmetic_shr_with_overflow(30);
        assert_eq!(a, (u64::MAX >> 30).into());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        a.arithmetic_shr_with_overflow(1);
        assert_eq!(a, (1_u64 << 63).into());

        let mut a: Bignum<10> = Bignum {
            limbs: [0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        a.arithmetic_shr_with_overflow(64);
        assert_eq!(a, 1u8.into());

        let mut a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        a.arithmetic_shr_with_overflow(7);
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
                    u64::MAX
                ],
            }
        );

        let mut a = Bignum {
            limbs: [0, u64::MAX, u64::MAX, 0, 0, 0, 0, 0b1000_0000, 0, u64::MAX],
        };
        a.arithmetic_shr_with_overflow(135);
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
                    u64::MAX,
                    u64::MAX,
                    u64::MAX,
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
            a << (64 - 7),
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
            a << (128 - 7),
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

    #[test]
    fn test_xgcd_bignums() {
        let n: Bignum<1> = "2b5".parse().unwrap();
        let r: Bignum<1> = "261".parse().unwrap();

        let (a, b, c) = Bignum::xgcd(&n, &r);
        assert_eq!(a, "-0xb5".parse().unwrap());
        assert_eq!(b, "0xce".parse().unwrap());
        assert_eq!(c, "0x15".parse().unwrap());

        let (a, b, c) = Bignum::xgcd(&r, &n);
        assert_eq!(a, "0xad".parse().unwrap());
        assert_eq!(b, "-0x98".parse().unwrap());
        assert_eq!(c, "0x15".parse().unwrap());

        let n: Bignum<26> = nist_consts::NIST_P.narrow();
        let r: Bignum<26> = Bignum::ONE << (24 * 64);
        let (a, b, c) = Bignum::xgcd(&r, &n);
        let a_true = "-0x2638276a12a55f53531790ef47ce2e065b6f8712eb2d4f945df25586114ea80ecb08ea78700f164701481a6ae936a66a760400cbe6523679e06a9f680d52428d3366bae6482534ba96d0a70880a249bc2e8c290779d16ed8e0add541dfc16d056da59bad2334090406f13c6a5af801c7680d84d576d3284792f94170bd15c35b230357d18d13ce51f1a9a948e882aed32aea6378ad8a3ab01d7e2bc45f87ede0ee9f341b39ebf102764140e1890a654da0a71c73887936ee5fb339532a224c26".parse().unwrap();
        let b_true = "0x2638276a12a55f535b4b4378bc8277ecf031263370ec7b7e0acdd4a302f48428dda8ce2446d179b3545d8b4497fb2bb0cdb94451bb92042084d355d080045cd25c77faf2432a1a533486195a5af0c129fe1dc78404679e96fe55bd1332ca3aecf2b229f4cf6cb52b844eed051e87ef3598913c33bf4956fa8ba10dfa570f6f77a011b71e04f5519d306216b0b2d0a6ab80d150971817dc5cdedea9ea69cef646e50da4c795c3bc85c1b6e18de48671bb0e8b93f735dc8cd7ffffffffffffffff".parse().unwrap();
        assert_eq!(a, a_true);
        assert_eq!(b, b_true);
        assert!(c.is_one());
    }

    #[test]
    fn test_bezouts_coeffs_bignums() {
        let N: Bignum<48> = nist_consts::NIST_P;
        let R: Bignum<48> = Bignum::ONE << (24 * 64);
        let n: Bignum<48> = N.narrow();
        let r: Bignum<48> = R.narrow();

        eprintln!("r = {r}");
        eprintln!("n = {n}");
        let (r_prime, n_prime) = Bignum::bezouts_coeffs(&r, &n);
        eprintln!("r_prime = {r_prime}");
        eprintln!("n_prime = {n_prime}");
        eprintln!("n_prime = {}", -n_prime);

        panic!()
    }
}
