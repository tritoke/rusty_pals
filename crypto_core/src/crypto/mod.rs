pub mod aes;
pub mod hmac;
pub mod md4;
pub mod oracle;
pub mod pad;

#[allow(unused)]
pub mod shs;

pub trait Hasher {
    type Digest: AsRef<[u8]>;

    const BLOCK_SIZE: usize;

    fn new() -> Self;

    fn update(&mut self, data: impl AsRef<[u8]>);

    fn finalize(&mut self);

    fn digest(&self) -> Self::Digest;

    fn reset(&mut self);

    fn set_message_len(&mut self, message_len: u64);
}
