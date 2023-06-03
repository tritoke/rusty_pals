pub mod aes;
pub mod md4;
pub mod oracle;
pub mod pad;
pub mod sha1;

pub trait Hasher {
    type Digest;

    fn new() -> Self;

    fn update(&mut self, data: impl AsRef<[u8]>);

    fn finalize(&mut self);

    fn digest(&self) -> Self::Digest;

    fn reset(&mut self);

    fn set_message_len(&mut self, message_len: u64);
}
