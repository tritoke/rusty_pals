pub mod xorshift32;
pub use xorshift32::XorShift32;
pub mod mt19937;
pub use mt19937::Mt19937;

use std::io::Read;

/// Generate a random, non-zero seed from /dev/urandom
fn gen_random_seed() -> u32 {
    let mut f = std::fs::File::open("/dev/urandom").expect("couldn't open /dev/urandom");
    let mut seed = [0u8; 4];
    f.read_exact(&mut seed)
        .expect("couldn't read seed from /dev/urandom");
    u32::from_le_bytes(seed)
}

pub trait Rng32 {
    /// Seed the generator
    fn seed(&mut self, seed: u32);

    /// Generate a 32 bit random value
    fn gen(&mut self) -> u32;

    /// Generate a random boolean value
    fn gen_bool(&mut self) -> bool {
        (self.gen() as i32) < 0
    }

    /// Generate a sequence of random bytes
    fn gen_bytes(&mut self, n: usize) -> Vec<u8> {
        std::iter::from_fn(|| Some(self.gen().to_le_bytes()))
            .flatten()
            .take(n)
            .collect()
    }

    /// Generate an array of random bytes
    fn gen_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        let bytes = std::iter::from_fn(|| Some(self.gen().to_le_bytes())).flatten();

        for (o, b) in out.iter_mut().zip(bytes) {
            *o = b;
        }

        out
    }
}

impl<T: Rng32> Rng32 for &mut T {
    fn seed(&mut self, seed: u32) {
        (*self).seed(seed)
    }

    fn gen(&mut self) -> u32 {
        (*self).gen()
    }
}
