use crate::rand::Rng32;
use std::io::Read;

#[derive(Debug, Copy, Clone)]
pub struct XorShift32 {
    state: u32,
}

impl Rng32 for XorShift32 {
    fn new() -> Self {
        let mut f = std::fs::File::open("/dev/urandom").expect("Couldn't open /dev/urandom");
        loop {
            let mut seed = [0u8; 4];
            f.read(&mut seed)
                .expect("Couldn't read seed from /dev/urandom");
            let state = u32::from_le_bytes(seed);
            if state != 0 {
                break Self { state };
            }
        }
    }

    fn from_seed(seed: u32) -> Self {
        assert!(seed != 0, "XorShift32 cannot be seeded with zero.");
        Self { state: seed }
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
        XorShift32::from_seed(0);
    }
}
