//! Base64 / base58 helpers and serde adapters for byte fields.

use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Encode bytes as standard (padded) base64.
pub fn to_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode standard base64.
pub fn from_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}

/// `#[serde(with = "encoding::b64")]` for `Vec<u8>` fields.
pub mod b64 {
    use super::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// `#[serde(default, with = "encoding::b64_opt")]` for `Option<Vec<u8>>`
/// fields.
pub mod b64_opt {
    use super::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => s.serialize_some(&STANDARD.encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// `#[serde(with = "encoding::b64_array")]` for `[u8; N]` fields.
pub mod b64_array {
    use super::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
        v.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes, got {}", v.len())))
    }
}
