use crate::rand::Rng32;

#[derive(Debug, Copy, Clone)]
pub struct XorShift32 {
    state: u32,
}

impl XorShift32 {
    pub fn new() -> Self {
        loop {
            let seed = crate::rand::gen_random_seed();
            if seed != 0 {
                break Self { state: seed };
            }
        }
    }
}

impl Default for XorShift32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Rng32 for XorShift32 {
    fn seed(&mut self, seed: u32) {
        assert!(seed != 0, "XorShift32 cannot be seeded with zero.");
        self.state = seed;
    }

    fn gen(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_xorshift32_zero_seed_fails() {
        let mut rng = XorShift32::new();
        rng.seed(0);
    }
}
