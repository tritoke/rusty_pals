/// Trait representing an Encryption Oracle
pub trait EncryptionOracle {
    fn encrypt(&self, data: impl AsRef<[u8]>) -> Vec<u8>;
}
