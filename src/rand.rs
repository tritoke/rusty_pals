#[derive(Debug, Copy, Clone)]
pub struct XorShift32 {
    state: u32,
}

impl XorShift32 {
    pub fn new(seed: u32) -> Self {
        assert!(seed != 0, "XorShift32 cannot be seeded with zero.");
        Self { state: seed }
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

    pub fn gen_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        let bytes = std::iter::from_fn(|| Some(self.gen().to_le_bytes())).flatten();

        for (o, b) in out.iter_mut().zip(bytes) {
            *o = b;
        }

        out
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic]
    fn test_zero_seed_fails() {
        XorShift32::new(0);
    }

    #[test]
    fn test_bytegen() {
        let mut rng = XorShift32::new(42);
        let a = rng.gen();
        let b = rng.gen();
        let [b1, b2, b3, b4] = a.to_le_bytes();
        let [b5, b6, b7, b8] = b.to_le_bytes();

        let correct = vec![b1, b2, b3, b4, b5, b6, b7, b8];
        let gen: Vec<u8> = XorShift32::new(42).gen_bytes(8);

        assert_eq!(gen, correct);
    }
}
