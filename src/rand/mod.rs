pub mod xorshift32;
pub use xorshift32::XorShift32;
pub mod mt19937;
pub use mt19937::Mt19937;

pub trait Rng32 {
    /// Seed from /dev/urandom
    fn new() -> Self;

    /// Create RNG from seed
    fn from_seed(seed: u32) -> Self;

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
