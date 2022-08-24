use std::collections::HashSet;
use std::hash::Hash;
use std::{mem, slice};

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

/// Cast a slice to a slice of arrays
fn cast_as_array<A, B, const N: usize>(slice: &[A]) -> &[[B; N]] {
    let num_elems = slice.len();
    let ptr = slice.as_ptr();

    // check the alignment of the pointer
    let align = mem::align_of::<B>();
    assert!(
        ptr as usize % align == 0,
        "Pointer is not sufficiently well aligned for the target type: {ptr:?} % {align} == {}.",
        ptr as usize % align
    );

    // calculate the number of destination element
    // ensure we have enough size in the slice
    let arr_size = mem::size_of::<[B; N]>();
    let orig_size = mem::size_of::<A>() * num_elems;
    assert!(orig_size % arr_size == 0, "Destination arrays do not evenly divide the source slice's size. {orig_size} % {arr_size} == {}", orig_size / arr_size);
    let new_num_elems = orig_size / arr_size;

    // SAFETY:
    // - References must always be aligned, the check in the first assert! checks this
    // - References must always have a valid length, the second assert! checks this
    unsafe { slice::from_raw_parts(ptr as *const _, new_num_elems) }
}

/// Cast a mutable slice to a mutable slice of arrays
fn cast_as_array_mut<A, B, const N: usize>(slice: &mut [A]) -> &mut [[B; N]] {
    let num_elems = slice.len();
    let ptr = slice.as_ptr();

    // check the alignment of the pointer
    let align = mem::align_of::<B>();
    assert!(
        ptr as usize % align == 0,
        "Pointer is not sufficiently well aligned for the target type: {ptr:?} % {align} == {}.",
        ptr as usize % align
    );

    // calculate the number of destination element
    // ensure we have enough size in the slice
    let arr_size = mem::size_of::<[B; N]>();
    let orig_size = mem::size_of::<A>() * num_elems;
    assert!(orig_size % arr_size == 0, "Destination arrays do not evenly divide the source slice's size. {orig_size} % {arr_size} == {}", orig_size / arr_size);
    let new_num_elems = orig_size / arr_size;

    // SAFETY:
    // - References must always be aligned, the check in the first assert! checks this
    // - References must always have a valid length, the second assert! checks this
    unsafe { slice::from_raw_parts_mut(ptr as *mut _, new_num_elems) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cast_as_array() {
        let input: Vec<u32> = (0..16).collect();
        let arrays: &[[u32; 4]] = cast_as_array(&input[..]);
        assert_eq!(
            arrays,
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        );
    }

    #[test]
    #[should_panic]
    fn test_cast_as_array_unaligned_fails() {
        let input: Vec<u32> = (0..16).collect();
        if input.as_ptr() as usize % 8 == 4 {
            // unaligned case
            let arrays: &[[u64; 2]] = cast_as_array(&input[..]);
        } else {
            // artificially create an unaligned access
            let arrays: &[[u64; 1]] = cast_as_array(&[1..=8]);
        }
    }

    #[test]
    fn test_cast_as_array_mut() {
        let mut input: Vec<u32> = (0..4).collect();
        let arrays: &mut [[u8; 4]] = cast_as_array_mut(&mut input[..]);
        arrays[0] = [0xFF; 4];
        assert_eq!(input, [0xFFFFFFFF, 1, 2, 3]);
    }

    #[test]
    #[should_panic]
    fn test_cast_as_array_mut_unaligned_fails() {
        let mut input: Vec<u32> = (0..16).collect();
        if input.as_ptr() as usize % 8 == 4 {
            // unaligned case
            let arrays: &mut [[u64; 2]] = cast_as_array_mut(&mut input[..]);
        } else {
            // artificially create an unaligned access
            let arrays: &mut [[u64; 1]] = cast_as_array_mut(&mut [1..=8]);
        }
    }
}
