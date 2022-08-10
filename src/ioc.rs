/// Letter frequencies for letters A-Z in order
/// https://en.wikipedia.org/wiki/Letter_frequency
const ALPHA_FREQ: [f64; 26] = [
    8.2, 1.5, 2.8, 4.3, 13.0, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7, 7.5, 1.9, 0.095, 6.0,
    6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074,
];

/// Letter frequencies for A-Z + space in order
const ALPHA_SPACE_FREQ: [f64; 27] = [
    6.52, 1.25, 2.10, 3.52, 10.26, 1.91, 1.61, 5.08, 5.64, 0.11, 0.60, 3.31, 2.08, 5.63, 6.19,
    1.46, 0.09, 4.86, 5.17, 7.41, 2.31, 0.80, 1.81, 0.14, 1.55, 0.06, 18.39,
];

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Alphabet {
    /// alphabet of A-Z
    Alpha,
    /// alphabet of A-Z + space
    AlphaSpace,
}

impl Alphabet {
    /// Return the number of characters in each alphabet
    pub fn num_chars(&self) -> usize {
        match self {
            Alphabet::Alpha => 26,
            Alphabet::AlphaSpace => 27,
        }
    }

    /// Return the character frequencies for this alphabet
    pub fn freqs(&self) -> &'static [f64] {
        match self {
            Alphabet::Alpha => &ALPHA_FREQ,
            Alphabet::AlphaSpace => &ALPHA_SPACE_FREQ,
        }
    }
}

/// Calculate the expected index of coincidence from a character distribution
/// https://en.wikipedia.org/wiki/Index_of_coincidence
fn ioc_from_dist(dist: &[f64]) -> f64 {
    let c = dist.len() as f64;
    dist.iter().map(|f| f * f).sum::<f64>() / (1.0 / c)
}

// pub fn ioc(text: impl AsRef<[u8]>) -> f64 {
//
// }

/// Count the percentage frequencies of each alphabetic character in the text
/// ```
/// use rusty_pals::ioc::{count_freq, Alphabet};
/// assert_eq!(count_freq("EEEEEE", Alphabet::Alpha)[(b'E' - b'A') as usize], 100.0);
/// ```
pub fn count_freq(text: impl AsRef<[u8]>, alpha: Alphabet) -> Vec<f64> {
    let mut counts = vec![0; alpha.num_chars()];

    for char in text.as_ref() {
        match char {
            b'a'..=b'z' => counts[(char - b'a') as usize] += 1,
            b'A'..=b'Z' => counts[(char - b'A') as usize] += 1,
            b' ' if alpha == Alphabet::AlphaSpace => counts[26] += 1,
            _ => (),
        }
    }

    let total: usize = counts.iter().sum();
    if total == 0 {
        // don't return an array of NaN...
        counts.into_iter().map(|x| x as f64).collect()
    } else {
        counts
            .into_iter()
            .map(|x| (x as f64 / total as f64) * 100.0)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_freq_alpha() {
        let counts = count_freq(
            "a1b324cdef #';;;ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Alphabet::Alpha,
        );
        assert_eq!(counts, vec![(2.0 / 52.0) * 100.0; 26]);
    }

    #[test]
    fn test_count_freq_alphaspace() {
        let counts = count_freq(
            "a1b324cdef#';;;ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ  ",
            Alphabet::AlphaSpace,
        );
        assert_eq!(counts, vec![(2.0 / 54.0) * 100.0; 27]);
    }

    #[test]
    fn test_ioc_from_dist() {
        let counts = vec![1.0 / 27.0; 27];
        assert!(f64::abs(ioc_from_dist(&counts) - 1.0) <= 1e-9);
    }
}
