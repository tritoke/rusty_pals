use std::cmp::Ordering;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Neg, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

use crate::bignum::Bignum;

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

    pub(super) fn sub_with_overflow(&mut self, rhs: &Self) -> bool {
        let mut carry = false;
        for (l, r) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            let (sum, overflow) = borrowing_sub(*l, *r, carry);
            *l = sum;
            carry = overflow;
        }
        carry
    }

    pub(super) fn negate(&mut self) {
        let mut carry = true;
        for l in self.limbs.iter_mut() {
            let (sum, overflow) = carrying_add(!*l, 0, carry);
            *l = sum;
            carry = overflow;
        }
    }

    pub(super) fn mul_with_overflow(&mut self, rhs: &Self) -> bool {
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

    pub(super) fn shr_with_overflow(&mut self, rhs: u32) -> bool {
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

    pub(super) fn shl_with_overflow(&mut self, rhs: u32) -> bool {
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

    pub(super) fn arithmetic_shr_with_overflow(&mut self, rhs: u32) -> bool {
        // first determine the fill limb
        let fill_limb = if (self.limbs[LIMBS - 1] >> 63) == 0 {
            u64::MIN
        } else {
            u64::MAX
        };

        if rhs as usize >= LIMBS * 64 {
            self.limbs.fill(fill_limb);
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

            let upper = fill_limb << (64 - limb_split_pos);
            let lower = self.limbs[LIMBS - 1] >> limb_split_pos;
            self.limbs[LIMBS - bottom_limb - 1] = upper | lower;
        }

        for i in 0..bottom_limb {
            self.limbs[LIMBS - i - 1] = fill_limb;
        }

        false
    }

    pub(super) fn is_negative(&self) -> bool {
        (self.limbs[LIMBS - 1] >> 63) == 1
    }

    pub(super) fn bitwise_and(&mut self, rhs: &Self) {
        for (o, i) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            *o &= *i;
        }
    }

    pub(super) fn bitwise_or(&mut self, rhs: &Self) {
        for (o, i) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            *o |= *i;
        }
    }

    pub(super) fn bitwise_xor(&mut self, rhs: &Self) {
        for (o, i) in self.limbs.iter_mut().zip(rhs.limbs.iter()) {
            *o ^= *i;
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
    use super::*;

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
}
