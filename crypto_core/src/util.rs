use std::array::TryFromSliceError;
use std::collections::HashSet;
use std::hash::Hash;
use std::slice;

#[derive(Debug, Copy, Clone)]
pub enum CastError {
    CastFail(TryFromSliceError),
    RaggedSlice,
}

impl std::fmt::Display for CastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CastError {}

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

/// \[T\]::as_chunks isn't stable yet, so I wrote my own :)
pub fn as_chunks<T, const N: usize>(slice: &[T]) -> (&[[T; N]], &[T]) {
    // SAFETY: len * N is always less than or equal to slice.len()
    // len * N is also always guaranteed to be divisible by N
    // thus it is safe to create `len` arrays of length N from that slice
    let len = slice.len() / N;
    let (array_slice, remainder) = slice.split_at(len * N);
    let arrays = unsafe { slice::from_raw_parts(array_slice.as_ptr().cast(), len) };

    (arrays, remainder)
}

/// \[T\]::as_chunks_mut isn't stable yet, so I wrote my own :)
pub fn as_chunks_mut<T, const N: usize>(slice: &mut [T]) -> (&mut [[T; N]], &mut [T]) {
    // SAFETY: len * N is always less than or equal to slice.len()
    // len * N is also always guaranteed to be divisible by N
    // thus it is safe to create `len` arrays of length N from that slice
    let len = slice.len() / N;
    let (array_slice, remainder) = slice.split_at_mut(len * N);
    let arrays = unsafe { slice::from_raw_parts_mut(array_slice.as_mut_ptr().cast(), len) };

    (arrays, remainder)
}

/// Cast a slice to an array, panics if the slice is not long enough
#[rustfmt::skip]
pub fn cast_as_array<T, const N: usize>(slice: &[T]) -> &[T; N] {
    slice.try_into().expect("Failed to cast as array.")
}

/// Cast a mutable slice to a mutable array, panics if the slice is not long enough
#[rustfmt::skip]
pub fn cast_as_array_mut<T, const N: usize>(slice: &mut [T]) -> &mut [T; N] {
    slice.try_into().expect("Failed to cast as array.")
}

/// Cast a slice to a slice of arrays
#[rustfmt::skip]
pub fn cast_as_arrays<T, const N: usize>(slice: &[T]) -> &[[T; N]] {
    let (arrays, rmdr) = as_chunks(slice);
    assert!(rmdr.is_empty(), "Slice length does not evenly divide into arrays.");
    arrays
}

/// Cast a mutable slice to a mutable slice of arrays
#[rustfmt::skip]
pub fn cast_as_arrays_mut<T, const N: usize>(slice: &mut [T]) -> &mut [[T; N]] {
    let (arrays, rmdr) = as_chunks_mut(slice);
    assert!(rmdr.is_empty(), "Slice length does not evenly divide into arrays.");
    arrays
}

/// Cast a slice to an array, panics if the slice is not long enough
#[rustfmt::skip]
pub fn try_cast_as_array<T, const N: usize>(slice: &[T]) -> Result<&[T; N], CastError> {
    slice.try_into().map_err(CastError::CastFail)
}

/// Cast a mutable slice to a mutable array, panics if the slice is not long enough
#[rustfmt::skip]
pub fn try_cast_as_array_mut<T, const N: usize>(slice: &mut [T]) -> Result<&mut [T; N], CastError> {
    slice.try_into().map_err(CastError::CastFail)
}

/// Cast a slice to a slice of arrays
#[rustfmt::skip]
pub fn try_cast_as_arrays<T, const N: usize>(slice: &[T]) -> Result<&[[T; N]], CastError> {
    let (arrays, rmdr) = as_chunks(slice);
    if !rmdr.is_empty() {
        return Err(CastError::RaggedSlice);
    }
    Ok(arrays)
}

/// Cast a mutable slice to a mutable slice of arrays
#[rustfmt::skip]
pub fn try_cast_as_arrays_mut<T, const N: usize>(slice: &mut [T]) -> Result<&mut [[T; N]], CastError> {
    let (arrays, rmdr) = as_chunks_mut(slice);
    if !rmdr.is_empty() {
        return Err(CastError::RaggedSlice);
    }
    Ok(arrays)
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

    #[test]
    fn test_try_cast_as_arrays() -> Result<(), CastError> {
        let input: Vec<u32> = (0..16).collect();
        let arrays: &[[u32; 4]] = try_cast_as_arrays(&input[..])?;
        assert_eq!(
            arrays,
            [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        );

        Ok(())
    }

    #[test]
    fn test_try_cast_as_arrays_size_mismatch_fails() {
        let input: Vec<u32> = (0..10).collect();
        assert!(try_cast_as_arrays::<_, 4>(&input[..]).is_err());
    }

    #[test]
    fn test_try_cast_as_arrays_mut() -> Result<(), CastError> {
        let mut input: Vec<u8> = (0..16).collect();
        let arrays: &mut [[u8; 4]] = try_cast_as_arrays_mut(&mut input[..])?;
        arrays[0] = [0xFF; 4];
        assert_eq!(
            input,
            [0xFF, 0xFF, 0xFF, 0xFF, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );

        Ok(())
    }

    #[test]
    fn test_try_cast_as_arrays_mut_size_mismatch_fails() {
        let mut input: Vec<u32> = (0..10).collect();
        assert!(try_cast_as_arrays_mut::<_, 4>(&mut input[..]).is_err());
    }

    #[test]
    fn test_try_cast_as_array() -> Result<(), CastError> {
        let input: Vec<u8> = (0..16).collect();
        let arrays: &[u8; 16] = try_cast_as_array(&input[..])?;
        assert_eq!(
            *arrays,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        Ok(())
    }

    #[test]
    fn test_try_cast_as_array_wrong_length_fails() {
        let input: Vec<u8> = (0..15).collect();
        assert!(try_cast_as_array::<_, 16>(&input[..]).is_err());
    }

    #[test]
    fn test_try_cast_as_array_mut() -> Result<(), CastError> {
        let mut input: Vec<u8> = (0..16).collect();
        let arrays: &mut [u8; 16] = try_cast_as_array_mut(&mut input[..])?;
        arrays[0] = 0xFF;
        assert_eq!(
            input,
            [0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );

        Ok(())
    }

    #[test]
    fn test_try_cast_as_array_mut_wrong_length_fails() {
        let mut input: Vec<u8> = (0..15).collect();
        assert!(try_cast_as_array_mut::<_, 16>(&mut input[..]).is_err());
    }
}
