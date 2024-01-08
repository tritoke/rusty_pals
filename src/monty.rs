use crate::bignum::Bignum;

// use std::ops::{
//     Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign,
//     Mul, MulAssign, Not, Rem, RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
// };

pub struct Monty<const LIMBS: usize> {
    num: Bignum<LIMBS>,
    modulus: Bignum<LIMBS>,
    // r: Bignum<LIMBS>,
    // r_prime: Bignum<LIMBS>,
}

impl<const LIMBS: usize> Monty<LIMBS> {
    fn new(z: &Bignum<LIMBS>, m: Bignum<LIMBS>) -> Self {
        Monty {
            num: *z,
            modulus: m,
        }
    }

    fn add(&mut self, rhs: &Self) {
        debug_assert!(self.modulus == rhs.modulus);

        self.num += rhs.num;
        if self.num > self.modulus {
            self.num -= &self.modulus;
        }
    }

    fn sub(&mut self, rhs: &Self) {
        debug_assert!(self.modulus == rhs.modulus);

        if rhs.num > self.num {
            self.num += self.modulus;
        }
        self.num -= rhs.num;
    }

    fn mul(&mut self, rhs: &Self) {
        todo!()
    }
}
