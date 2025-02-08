// TODO: If const-fn in traits is ever stabilised replace this with a const trait...
// (I can dream...)
macro_rules! impl_ct_select {
    ($name:ident, $num_ty:ty) => {
        pub const fn $name(a: $num_ty, b: $num_ty, bit: $num_ty) -> $num_ty {
            let isnonzero = (bit | bit.wrapping_neg()) >> (<$num_ty>::BITS - 1);
            let mask = isnonzero.wrapping_neg();
            (mask & (b ^ a)) ^ b
        }
    };
}

impl_ct_select!(select_u8, u8);
impl_ct_select!(select_u16, u16);
impl_ct_select!(select_u32, u32);
impl_ct_select!(select_u64, u64);
impl_ct_select!(select_u128, u128);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select() {
        assert_eq!(select_u8(1, 2, 0), 2);
        assert_eq!(select_u8(1, 2, 3), 1);
        assert_eq!(select_u16(1, 2, 0), 2);
        assert_eq!(select_u16(1, 2, 3), 1);
        assert_eq!(select_u32(1, 2, 0), 2);
        assert_eq!(select_u32(1, 2, 3), 1);
        assert_eq!(select_u64(1, 2, 0), 2);
        assert_eq!(select_u64(1, 2, 3), 1);
        assert_eq!(select_u128(1, 2, 0), 2);
        assert_eq!(select_u128(1, 2, 3), 1);
    }
}
