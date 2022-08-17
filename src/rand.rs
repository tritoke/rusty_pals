use color_eyre::eyre::{ensure, Result};

#[derive(Debug, Copy, Clone)]
pub struct XorShift32 {
    state: u32,
}

impl XorShift32 {
    pub fn new(seed: u32) -> Result<Self> {
        ensure!(seed != 0, "Zero seed is silly.");
        Ok(Self { state: seed })
    }

    pub fn gen(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        self.state
    }

    pub fn gen_bool(&mut self) -> bool {
        (self.gen() as i32) < 0
    }

    pub fn gen_bytes(&mut self, n: usize) -> Vec<u8> {
        std::iter::from_fn(|| Some(self.gen().to_le_bytes()))
            .flatten()
            .take(n)
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_zero_seed_fails() {
        assert!(XorShift32::new(0).is_err());
    }

    #[test]
    fn test_bytegen() {
        let mut rng = XorShift32::new(42).unwrap();
        let a = rng.gen();
        let b = rng.gen();
        let [b1, b2, b3, b4] = a.to_le_bytes();
        let [b5, b6, b7, b8] = b.to_le_bytes();

        let correct = vec![b1, b2, b3, b4, b5, b6, b7, b8];
        let gen: Vec<u8> = XorShift32::new(42).unwrap().gen_bytes(8);

        assert_eq!(gen, correct);
    }
}
