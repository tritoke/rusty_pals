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

    fn montgomery_reduction(&self, mut n: WideBignum<LIMBS>) -> Bignum<LIMBS> {
        // keep track of the carry past the end of the current multiply-accumulate
        let mut final_add_carry = false;
        for i in 0..LIMBS {
            let u = n.limb(i).wrapping_mul(self.m_prime);

            let mut carry = 0;
            for (j, limb) in n.limbs_mut().skip(i).take(LIMBS).enumerate() {
                // fuse the product with the modulus and addition of that into our wide number into
                // one operation:
                // https://en.wikipedia.org/wiki/Multiply-accumulate_operation
                let wide = *limb as u128 + u as u128 * self.m.limbs[j] as u128 + carry as u128;
                (*limb, carry) = (wide as u64, (wide >> 64) as u64);
            }

            let limb = n.limb_mut(LIMBS + i);
            (*limb, final_add_carry) = carrying_add(*limb, carry, final_add_carry);
        }

        let hi = n.into_high();
        if final_add_carry {
            let mut wide = WideBignum::new(Bignum::ONE, hi);
            wide.sub_with_overflow(&WideBignum::new_low(self.m));
            wide.into_low()
        } else if hi >= self.m {
            hi - self.m
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

        let mut out = Self {
            inner: self.info.r,
            info: self.info.clone(),
        };
        for i in (0..=t).rev() {
            out.multiplication(&out.clone());
            if exponent.test_bit(i) {
                out.multiplication(self);
            }
        }

        *self = out;
    }

    pub fn pow(&self, exponent: &Bignum<LIMBS>) -> Self {
        let mut out = self.clone();
        out.exponentation(exponent);
        out
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
        let pow = Bignum::from(g);
        let correct = "0xae1333a1cdfbc612abbf7b08106bde0956a1af2819b960441f2874856afde40704fb87cb6974d5a804da6adbf7d82d721fdb5ca99eff43eee606bac06c1bce01fee46d1f6bc502d26f72e2e1dce1b68278e3ebf9305860c94d7d14a524d4497ad0aac356e50797c19d4c418ed00e8cab12e724a331f2b3371e4fcbeb9d8c35e809bb6d3448b99978ba9353c1fba8ed87f6d2687cc85484d76475217ba300cc58edeeca3f3e58bc18b956c7deb8be85da8c0102512b008390c31a6eb751549960".parse().unwrap();
        assert_eq!(pow, correct);
    }
}
