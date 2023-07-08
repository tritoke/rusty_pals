use std::cmp::Ordering;
use std::fmt;
use std::fmt::Formatter;
use std::ops::{
    Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
    Mul, MulAssign, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Bignum<const LIMBS: usize> {
    limbs: [u64; LIMBS],
}

// utility functions
#[allow(dead_code)]
impl<const LIMBS: usize> Bignum<LIMBS> {
    const MAX: Self = Self {
        limbs: [u64::MAX; LIMBS],
    };

    const MIN: Self = Self {
        limbs: [u64::MIN; LIMBS],
    };

    const ZERO: Self = Self::MIN;

    const ONE: Self = {
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
        eprintln!("normalising_shift={normalising_shift}");
        debug_assert_eq!(dividend.leading_zeros(), divisor.leading_zeros());

        // initialize quotient and remainder
        let mut quotient = Bignum::ZERO;

        // perform the division
        while dividend >= rhs {
            eprintln!("dividend={dividend}\tdivisor={divisor}\tquotient={quotient}");
            quotient <<= 1;
            if dividend >= divisor {
                dividend -= divisor;
                quotient |= Bignum::ONE;
            }
            divisor >>= 1;
        }
        eprintln!("dividend={dividend}\tdivisor={divisor}\tquotient={quotient}");
        let remainder = dividend;
        quotient <<= 1 + divisor.bit_length() - rhs.bit_length();

        (quotient, remainder)
    }
}

impl<const LIMBS: usize> Default for Bignum<LIMBS> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const LIMBS: usize> fmt::Display for Bignum<LIMBS> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
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

        for r in rhs.limbs.iter() {
            let mut carry = 0;
            for (l, o) in self.limbs.iter().zip(out.limbs.iter_mut()) {
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
    }

    #[test]
    fn test_divmod_bignums() {
        let a: Bignum<10> = 5u8.into();
        let b: Bignum<10> = 6u8.into();
        assert_eq!(a.divmod(b), (0u8.into(), a));

        let a: Bignum<10> = 1234u16.into();
        let b: Bignum<10> = 56u8.into();
        assert_eq!(a.divmod(b), (22u8.into(), 2u8.into()));

        eprintln!("=====");
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
        eprintln!("{}", !(Bignum::<10>::MAX >> 50));
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
        // let a: Bignum<10> = Bignum {
        //     limbs: [0, 0, 0, 0, 0, 0, 0, 0, u64::MAX, 0],
        // };
        // assert_eq!(a.bit_length(), 64 * 9);
        assert_eq!(Bignum::<10>::MIN.bit_length(), 0);
        assert_eq!(Bignum::<10>::MAX.bit_length(), 64 * 10);
        assert_eq!((Bignum::<10>::MAX >> 50).bit_length(), 64 * 10 - 50);
    }
}
