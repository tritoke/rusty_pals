use color_eyre::eyre::Result;

mod base64;
mod hex;

pub use base64::{b64decode, b64encode};
pub use hex::{parse_hex, to_hex};

/// Trait allowing us to ues .encode_hex / .encode_b64 to encode bytes
pub trait Encodable {
    fn encode_hex(&self) -> String;
    fn encode_b64(&self) -> String;
}

impl Encodable for [u8] {
    fn encode_hex(&self) -> String {
        to_hex(self)
    }

    fn encode_b64(&self) -> String {
        b64encode(self)
    }
}

/// Trait allowing us to use .decode_hex / .decode_b64 to decode strings
pub trait Decodable {
    fn decode_hex(&self) -> Result<Vec<u8>>;
    fn decode_b64(&self) -> Result<Vec<u8>>;
}

impl Decodable for str {
    fn decode_hex(&self) -> Result<Vec<u8>> {
        parse_hex(self)
    }

    fn decode_b64(&self) -> Result<Vec<u8>> {
        b64decode(self)
    }
}
