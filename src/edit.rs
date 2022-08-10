pub fn edit_distance(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> u32 {
    a.as_ref()
        .iter()
        .zip(b.as_ref())
        .map(|(b1, b2)| (b1 ^ b2).count_ones())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_distance() {
        let dist = edit_distance("this is a test", "wokka wokka!!!");
        assert_eq!(dist, 37);
    }
}
