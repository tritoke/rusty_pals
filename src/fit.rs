/// A count of the ASCII letters from https://m.gutenberg.org/ebooks/15
/// by ASCII I mean character values 0-127
const ASCII_COUNTS: [u32; 128] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22627, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 197153, 1756, 22, 1, 4, 1, 6, 7, 232, 232, 75, 0, 19407, 2667, 7904, 11, 129, 155, 47,
    34, 27, 47, 25, 39, 49, 25, 214, 4177, 0, 0, 0, 1003, 0, 2544, 1414, 1296, 698, 1088, 787, 653,
    1442, 3723, 254, 147, 849, 669, 942, 695, 1241, 334, 796, 2020, 2467, 215, 268, 1262, 416, 277,
    20, 46, 0, 46, 0, 747, 0, 76656, 15791, 22106, 38133, 118246, 20458, 20625, 62308, 63280, 919,
    8083, 42593, 23021, 65805, 70083, 16627, 1250, 52759, 63081, 87440, 26923, 8584, 21283, 1046,
    16970, 624, 0, 0, 0, 0, 0,
];

/// Score a given ASCII plaintext on how likely it is to be an english plaintext
pub fn score_text(text: impl AsRef<[u8]>) -> u64 {
    let text = text.as_ref();
    text.iter()
        .map(|c| *ASCII_COUNTS.get(*c as usize).unwrap_or(&0) as u64)
        .sum::<u64>()
        / text.len() as u64
}

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
    fn test_score_text() {
        assert_eq!(
            score_text("abcde"),
            (76656 + 15791 + 22106 + 38133 + 118246) / 5
        );
    }

    #[test]
    fn test_edit_distance() {
        let dist = edit_distance("this is a test", "wokka wokka!!!");
        assert_eq!(dist, 37);
    }
}
