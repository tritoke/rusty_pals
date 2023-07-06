mod base64;
mod hex;

use crate::util::CastError;
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

#[derive(Debug, Copy, Clone)]
pub enum DecodingError {
    CastError(CastError),
    InvalidCharacter(u8),
}

impl std::fmt::Display for DecodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DecodingError {}

impl From<CastError> for DecodingError {
    fn from(value: CastError) -> Self {
        Self::CastError(value)
    }
}

/// Trait allowing us to use .decode_hex / .decode_b64 to decode strings
pub trait Decodable {
    type DecodeError;

    fn decode_hex(&self) -> Result<Vec<u8>, Self::DecodeError>;
    fn decode_b64(&self) -> Result<Vec<u8>, Self::DecodeError>;
}

impl Decodable for str {
    type DecodeError = DecodingError;

    fn decode_hex(&self) -> Result<Vec<u8>, Self::DecodeError> {
        parse_hex(self)
    }

    fn decode_b64(&self) -> Result<Vec<u8>, Self::DecodeError> {
        b64decode(self)
    }
}
