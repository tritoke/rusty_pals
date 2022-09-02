use std::collections::HashSet;
use std::hash::Hash;

/// Detect whether an iterator contains a duplicate element
pub fn has_duplicate<T>(it: impl IntoIterator<Item = T>) -> bool
where
    T: Eq + Hash,
{
    let mut set = HashSet::new();
    for i in it {
        if !set.insert(i) {
            return true;
        }
    }

    false
}

/// Cast a slice to an array, panics if the slice is not long enough
/// SAFETY: slice length is checked to be the same length as array
#[rustfmt::skip]
pub fn cast_as_array<T, const N: usize>(slice: &[T]) -> &[T; N] {
    assert_eq!(slice.len(), N, "Slice length does not match array length. {} != {N}", slice.len());
    slice.try_into().expect("Failed to cast as array.")
}

/// Cast a mutable slice to a mutable array, panics if the slice is not long enough
/// SAFETY: slice length is checked to be the same length as array
#[rustfmt::skip]
pub fn cast_as_array_mut<T, const N: usize>(slice: &mut [T]) -> &mut [T; N] {
    assert_eq!(slice.len(), N, "Slice length does not match array length. {} != {N}", slice.len());
    slice.try_into().expect("Failed to cast as array.")
}

/// Cast a slice to a slice of arrays
#[rustfmt::skip]
pub fn cast_as_arrays<T, const N: usize>(slice: &[T]) -> &[[T; N]] {
    let (pre, mid, post) = unsafe { slice.align_to() };
    assert!(pre.is_empty(), "Slice does not have sufficient alignment.");
    assert!(post.is_empty(), "Slice is not long enough to be sliced into arrays.");
    mid
}

/// Cast a mutable slice to a mutable slice of arrays
#[rustfmt::skip]
pub fn cast_as_arrays_mut<T, const N: usize>(slice: &mut [T]) -> &mut [[T; N]] {
    let (pre, mid, post) = unsafe { slice.align_to_mut() };
    assert!(pre.is_empty(), "Slice does not have sufficient alignment.");
    assert!(post.is_empty(), "Slice is not long enough to be sliced into arrays.");
    mid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cast_as_arrays() {
        let input: Vec<u32> = (0..16).collect();
        let arrays: &[[u32; 4]] = cast_as_arrays(&input[..]);
        assert_eq!(
            arrays,
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        );
    }

    #[test]
    #[should_panic]
    fn test_cast_as_arrays_size_mismatch_fails() {
        let input: Vec<u32> = (0..10).collect();
        assert_eq!(cast_as_arrays(&input[..]), [[0, 1, 2, 3], [4, 5, 6, 7]]);
    }

    #[test]
    fn test_cast_as_arrays_mut() {
        let mut input: Vec<u8> = (0..16).collect();
        let arrays: &mut [[u8; 4]] = cast_as_arrays_mut(&mut input[..]);
        arrays[0] = [0xFF; 4];
        assert_eq!(
            input,
            [0xFF, 0xFF, 0xFF, 0xFF, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    #[should_panic]
    fn test_cast_as_arrays_mut_size_mismatch_fails() {
        let mut input: Vec<u32> = (0..10).collect();
        assert_eq!(
            cast_as_arrays_mut(&mut input[..]),
            [[0, 1, 2, 3], [4, 5, 6, 7]]
        );
    }

    #[test]
    fn test_cast_as_array() {
        let input: Vec<u8> = (0..16).collect();
        let arrays: &[u8; 16] = cast_as_array(&input[..]);
        assert_eq!(
            *arrays,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    #[should_panic]
    fn test_cast_as_array_wrong_length_fails() {
        let input: Vec<u8> = (0..15).collect();
        let _arrays: &[u8; 16] = cast_as_array(&input[..]);
    }

    #[test]
    fn test_cast_as_array_mut() {
        let mut input: Vec<u8> = (0..16).collect();
        let arrays: &mut [u8; 16] = cast_as_array_mut(&mut input[..]);
        arrays[0] = 0xFF;
        assert_eq!(
            input,
            [0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    #[should_panic]
    fn test_cast_as_array_mut_wrong_length_fails() {
        let mut input: Vec<u8> = (0..15).collect();
        let _arrays: &mut [u8; 16] = cast_as_array_mut(&mut input[..]);
    }
}
