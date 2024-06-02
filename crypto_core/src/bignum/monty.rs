use std::cmp::Ordering;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use std::rc::Rc;

use super::{arith::carrying_add, wide::WideBignum, Bignum};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MontyInfo<const LIMBS: usize> {
    m: Bignum<LIMBS>,
    r: Bignum<LIMBS>,
    r_squared: Bignum<LIMBS>,
    m_prime: u64,
}

impl<const LIMBS: usize> MontyInfo<LIMBS> {
    pub fn new(modulus: Bignum<LIMBS>) -> Self {
        let mut r = Bignum::MAX;
        r %= &modulus;
        r.add_with_overflow(&Bignum::from(1_u8));

        let r2 = r.mul_wide(&r).remainder(&modulus);
        let b = Bignum::ONE << 64;
        let inv = modulus.inv_mod(&b);
        let m_inv = inv.limbs[0];
        debug_assert!(inv.limbs.iter().skip(1).all(|x| *x == 0));
        let m_prime = (-(m_inv as i64)) as u64;
        Self {
            m: modulus,
            m_prime,
            r,
            r_squared: r2,
        }
    }

    fn montgomery_reduction(&self, n: WideBignum<LIMBS>) -> Bignum<LIMBS> {
        let (mut hi, mut lo) = n.split();

        let mut outer_carry = false;
        for i in 0..LIMBS {
            let u = lo.limbs[i].wrapping_mul(self.m_prime);
            let (prod, prod_carry) = self.m.mul_with_limb(u);

            let mut carry = false;
            for j in 0..=LIMBS + 1 {
                let k = i + j;
                // let ai = n.limb_mut(k);
                let ai = if k < LIMBS {
                    &mut lo.limbs[k]
                } else if k < LIMBS * 2 {
                    &mut hi.limbs[k - LIMBS]
                } else {
                    break;
                };

                let to_add = match j.cmp(&LIMBS) {
                    Ordering::Less => prod.limbs[j],
                    Ordering::Equal => prod_carry,
                    Ordering::Greater => 0,
                };

                (*ai, carry) = carrying_add(*ai, to_add, carry);
            }

            if i + 1 < LIMBS {
                (hi.limbs[i + 1], outer_carry) =
                    carrying_add(hi.limbs[i + 1], outer_carry as _, carry);
            } else if outer_carry ^ carry {
                outer_carry |= carry;
            } else if outer_carry & carry {
                unreachable!("I really hope I don't get here");
            }
        }

        if outer_carry {
            // AHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
            let mut wide = WideBignum::new(Bignum::ONE, hi);
            wide.sub_with_overflow(&WideBignum::new_low(self.m));
            wide.split().1
        } else {
            hi
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MontyForm<const LIMBS: usize> {
    info: Rc<MontyInfo<LIMBS>>,
    inner: Bignum<LIMBS>,
}

#[allow(unused)]
impl<const LIMBS: usize> MontyForm<LIMBS> {
    pub fn new(num: &Bignum<LIMBS>, info: Rc<MontyInfo<LIMBS>>) -> Self {
        let inner = info.montgomery_reduction(num.mul_wide(&info.r_squared));
        Self { info, inner }
    }

    fn addition(&mut self, rhs: &Self) {
        debug_assert!(self.inner < self.info.m);
        debug_assert!(rhs.inner < self.info.m);
        let overflow = self.inner.add_with_overflow(&rhs.inner);
        if overflow || self.inner >= self.info.m {
            self.inner.sub_with_overflow(&self.info.m);
        }
    }

    fn subtraction(&mut self, rhs: &Self) {
        debug_assert!(self.inner < self.info.m);
        debug_assert!(rhs.inner < self.info.m);
        if self.inner < rhs.inner {
            self.inner.add_with_overflow(&self.info.m);
        }
        self.inner.sub_with_overflow(&rhs.inner);
    }

    fn multiplication(&mut self, rhs: &Self) {
        debug_assert!(self.inner < self.info.m);
        debug_assert!(rhs.inner < self.info.m);
        self.inner = self
            .info
            .montgomery_reduction(self.inner.mul_wide(&rhs.inner));
    }

    fn exponentation(&mut self, exponent: &Bignum<LIMBS>) {
        if exponent.is_zero() {
            self.inner = self.info.r;
            return;
        }

        let t = (LIMBS * 64) - exponent.leading_zeros() as usize - 1;
        debug_assert!(exponent.test_bit(t));

        let mut out = Self::new(&self.info.r, self.info.clone());
        for i in (0..=t).rev() {
            out.multiplication(&out.clone());
            if exponent.test_bit(i) {
                out.multiplication(self);
            }
        }

        *self = out;
    }
}

impl<const LIMBS: usize> From<MontyForm<LIMBS>> for Bignum<LIMBS> {
    fn from(value: MontyForm<LIMBS>) -> Self {
        value
            .info
            .montgomery_reduction(WideBignum::new_low(value.inner))
    }
}

super::arith::bignum_arith_impls!(
    MontyForm<LIMBS>,
    MontyForm<LIMBS>,
    allow_rhs_ref,
    Add,
    add,
    AddAssign,
    add_assign,
    addition,
    no_overflow
);

super::arith::bignum_arith_impls!(
    MontyForm<LIMBS>,
    MontyForm<LIMBS>,
    allow_rhs_ref,
    Sub,
    sub,
    SubAssign,
    sub_assign,
    subtraction,
    no_overflow
);

super::arith::bignum_arith_impls!(
    MontyForm<LIMBS>,
    MontyForm<LIMBS>,
    allow_rhs_ref,
    Mul,
    mul,
    MulAssign,
    mul_assign,
    multiplication,
    no_overflow
);

#[cfg(test)]
mod test {
    use crate::bignum::nist;

    use super::*;

    #[test]
    fn test_montyinfo_new() {
        let monty_info = MontyInfo::new(nist::NIST_P);
        assert!(monty_info.m == nist::NIST_P);
        assert_eq!(monty_info.m_prime, 1);
        let r: Bignum<24> = "0x000000000000000036F0255DDE973DCB3B399D747F23E32ED6FDB1F77598338BFDF44159C4EC64DDAEB5F78671CBFB22106AE64C32C5BCE4CFD4F5920DA0EBC8B01ECA9292AE3DBA1B7A4A899DA181390BB3BD1659C81294F400A3490BF9481211C79404A576605A5160DBEE83B4E019B6D799AE131BA4C23DFF83475E9C40FA6725B7C9E3AA2C6596E9C05702DB30A07C9AA2DC235C5269E39D0CA9DF7AAD44612AD6F88F69699298F3CAB1B54367FB0E8B93F735DC8CD80000000000000001".parse().unwrap();
        assert_eq!(monty_info.r, r);
        let r_squared: Bignum<24> = "0xE3B33C7259541C01EE9C9A216CC1EBD2AE5941047929A1C7E9C3FA02CC2456EF102630FA9A36A51F57B59348679844600BE49647A87C7B37F8056564969B7F02DC541A4ED4053F54D62A0EEAB270521B22C296E9D46FEC238E1ABD780223B76BB8FE6121196B7E881C729C7E04B9F79607CD0A628E43413004A541FF93AE1CEBB004A750DB102D39B9052BB47A58F1707E8CD2AC98B5FB628F2331B13B01E018F466EE5FBCD49D68D0AB92E18397F2458E0E3E2167478C73F115D27D32C695E0".parse().unwrap();
        assert_eq!(monty_info.r_squared, r_squared);
    }

    #[test]
    fn test_montyform_roundtrip() {
        let monty_info = Rc::new(MontyInfo::new(nist::NIST_P));
        for i in 0u64..100 {
            let bn = i.into();
            let mf = MontyForm::new(&bn, monty_info.clone());
            assert_eq!(Bignum::from(mf), bn);
        }

        for i in 1u64..=100 {
            let mut bn = monty_info.m;
            bn -= Bignum::from(i);
            let mf = MontyForm::new(&bn, monty_info.clone());
            assert_eq!(Bignum::from(mf), bn);
        }
    }

    #[test]
    fn test_montyform_addition_roundtrip() {
        let monty_info = Rc::new(MontyInfo::new(nist::NIST_P));
        for x in 0u64..50 {
            for y in 0u64..50 {
                let xn = x.into();
                let xmf = MontyForm::new(&xn, monty_info.clone());
                let yn = y.into();
                let ymf = MontyForm::new(&yn, monty_info.clone());
                let zmf = xmf + ymf;
                let zn = xn + yn;
                assert_eq!(Bignum::from(zmf), zn);
            }
        }
    }

    #[test]
    fn test_montyform_subtraction_roundtrip() {
        let monty_info = Rc::new(MontyInfo::new(nist::NIST_P));
        for x in 0u64..50 {
            for y in 0u64..50 {
                let xn = x.into();
                let xmf = MontyForm::new(&xn, monty_info.clone());
                let yn = y.into();
                let ymf = MontyForm::new(&yn, monty_info.clone());
                let zmf = xmf - ymf;
                let zn = if x >= y {
                    xn - yn
                } else {
                    (monty_info.m - yn) + xn
                };
                assert_eq!(Bignum::from(zmf), zn);
            }
        }
    }

    #[test]
    fn test_montyform_multiplication_roundtrip() {
        let monty_info = Rc::new(MontyInfo::new(nist::NIST_P));
        for x in 0u64..50 {
            for y in 0u64..50 {
                let xn = x.into();
                let xmf = MontyForm::new(&xn, monty_info.clone());
                let yn = y.into();
                let ymf = MontyForm::new(&yn, monty_info.clone());
                let zmf = xmf * ymf;
                let zn = xn * yn;
                assert_eq!(Bignum::from(zmf), zn);
            }
        }
    }

    #[test]
    fn test_montyform_exponentation() {
        let monty_info = Rc::new(MontyInfo::new(nist::NIST_P));
        let mut g = MontyForm::new(&Bignum::from(2u8), monty_info.clone());
        let e: Bignum<24> = "0x34df1e8fb415e7164863df9ca4b97e0bb582c8405b2116f83d2ce74601da0229ba7a643004167d7ac68a579e47815e448253b4fe7f4cdd03711c8f4fea262cae30538bea04662bf134cb141fa214d6c65145a1cc28f4f110903c107a7b7b56c33ed8c7d0364e368928b75ca0a8b9eb058a7a855ebf6254c96da6df68ee7524472c2b25015326303a9b3e5742132723f73741abf0a9e5398690ee841b90377ce7a57f3554f2b62957371b24b6f2d945c1135a30b0c946f65183bfddcca23d70".parse().unwrap();
        g.exponentation(&e);
        let correct = "0x23e4dd0851fcf1a15d3217a3458d6e26a7c54a8fbe0d029c7c35c3f8e1da06321bf0bc1a52432c2077f03c4584a883348ca4cc7abe017732e743f4dca16dd2823ade5894c761bb7f1e3654fde54c7eab90a12e26d22120851ff0e89969faf51ec0de17f1dabff11cbfc8b5f0c288662f2fb736ce0948180609c3d47587e80c835d81587540e6c071d69f29cdf96d874631d1329de977ccb236255cf878fecaf7d2cfac23b0102575ac177a82ecd7e1cb62e1efd7d4aa0f2bc71898a173313507".parse().unwrap();
        dbg!(correct);
        assert_eq!(dbg!(Bignum::from(g)), correct);
    }
}
