use std::cmp::Ordering;
use std::rc::Rc;

use super::{arith::carrying_add, Bignum};

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

        let r2 = Bignum::MAX;
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

    fn montgomery_reduction(&self, lower: &Bignum<LIMBS>, upper: &Bignum<LIMBS>) -> Bignum<LIMBS> {
        let mut lower = *lower;
        let mut upper = *upper;

        for i in 0..LIMBS {
            let u = lower.limbs[i].wrapping_mul(self.m_prime);
            let (prod, prod_carry) = self.m.mul_with_limb(u);

            let mut carry = false;
            for j in 0..=LIMBS + (i < LIMBS - 1) as usize {
                let to_add = match j.cmp(&LIMBS) {
                    Ordering::Less => prod.limbs[j],
                    Ordering::Equal => prod_carry,
                    Ordering::Greater => carry as u64,
                };

                let k = i + j;
                let ai = if k < LIMBS {
                    &mut lower.limbs[k]
                } else {
                    &mut upper.limbs[k - LIMBS]
                };

                let (sum, overflow) = carrying_add(*ai, to_add, carry);
                *ai = sum;
                carry = overflow;
            }
            debug_assert!(!carry);
        }

        if upper > self.m {
            upper -= &self.m;
        }

        upper
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MontyForm<const LIMBS: usize> {
    info: Rc<MontyInfo<LIMBS>>,
    inner: Bignum<LIMBS>,
}

impl<const LIMBS: usize> MontyForm<LIMBS> {
    pub fn new(num: &Bignum<LIMBS>, info: Rc<MontyInfo<LIMBS>>) -> Self {
        let inner = info.montgomery_reduction(num, &Bignum::ZERO);
        Self { info, inner }
    }
}

impl<const LIMBS: usize> From<MontyForm<LIMBS>> for Bignum<LIMBS> {
    fn from(value: MontyForm<LIMBS>) -> Self {
        value.info.montgomery_reduction(&Bignum::ZERO, &value.inner)
    }
}

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
        // let mf = MontyForm::new(&0u8.into(), monty_info.clone());
        // assert_eq!(mf.inner, Bignum::from(0_u32));
        let mf = MontyForm::new(&1u8.into(), monty_info.clone());
        assert_eq!(mf.inner, Bignum::from(monty_info.r));
        // let mf = MontyForm::new(&2u8.into(), monty_info.clone());
        // assert_eq!(mf.inner, Bignum::from(monty_info.r));
        // for i in 0u64..10 {
        //     eprintln!("{i}");
        //     let bn = i.into();
        //     let mf = MontyForm::new(&bn, monty_info.clone());
        //     assert_eq!(Bignum::from(mf), bn);
        // }
    }
}
