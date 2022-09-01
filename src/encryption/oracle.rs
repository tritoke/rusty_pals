use color_eyre::eyre::Result;

/// Trait representing an Encryption Oracle
pub trait EncryptionOracle {
    fn encrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>>;
}
