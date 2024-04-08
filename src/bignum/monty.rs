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
        r.add_with_overflow(1);

        let r2
        let b = Bignum::ONE << 64;
        let inv = modulus.inv_mod(&b);
        let m_inv = inv.limbs[0];
        debug_assert!(inv.limbs.iter().skip(1).all(|x| *x == 0));
        let m_prime = (-(m_inv as i64)) as u64;
        Self {
            m: modulus,
            m_prime,
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
    }

    #[test]
    fn test_montyform_roundtrip() {
        let monty_info = Rc::new(MontyInfo::new(nist::NIST_P));
        for i in 0u64..10 {
            let bn = i.into();
            let mf = MontyForm::new(&bn, monty_info.clone());
            assert_eq!(Bignum::from(mf), bn);
        }
    }
}
