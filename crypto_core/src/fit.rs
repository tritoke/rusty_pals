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

// yoinked from https://github.com/tritoke/aes_observed_done_fast
pub fn pearson_correlation(x: &[f64], y: &[f64]) -> f64 {
    // implementation of the iterative update formulas from: https://crypto.fit.cvut.cz/sites/default/files/publications/fulltexts/pearson.pdf
    assert_eq!(x.len(), y.len());

    let [_, _, m2x, m2y, c2s] = x.iter().zip(y.iter()).enumerate().fold(
        [0.0_f64; 5],
        |[x_bar_, y_bar_, m2x_, m2y_, c2s_], (n, (&x, &y))| {
            let n = n as f64;

            // update the means
            let x_bar = x_bar_ + ((x - x_bar_) / (n + 1.0));
            let y_bar = y_bar_ + ((y - y_bar_) / (n + 1.0));

            // update the sums
            let m2x = m2x_ + (x - x_bar) * (x - x_bar_);
            let m2y = m2y_ + (y - y_bar) * (y - y_bar_);

            // update the covariance
            let c2s = c2s_ + (n / (n + 1.0)) * (x - x_bar_) * (y - y_bar_);

            [x_bar, y_bar, m2x, m2y, c2s]
        },
    );

    c2s / (m2x.sqrt() * m2y.sqrt())
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
