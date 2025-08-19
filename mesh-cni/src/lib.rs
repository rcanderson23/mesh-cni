pub mod add;
pub mod bpf;
pub mod check;
pub mod config;
pub mod delete;
pub mod error;
pub mod gc;
pub mod response;
pub mod types;
pub mod version;

use std::fmt::Display;
use std::str::FromStr;

use semver::Version;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::Error;

pub const CNI_VERSION: Version = Version::new(1, 1, 0);
pub const SUPPORTED_CNI_VERSION: [Version; 4] = [
    Version::new(0, 3, 1),
    Version::new(0, 4, 1),
    Version::new(1, 0, 0),
    Version::new(1, 1, 0),
];

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn serialize_to_string<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: ToString,
{
    value.to_string().serialize(serializer)
}

pub(crate) fn serialize_to_string_slice<S, T>(
    values: &[T],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: ToString,
{
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .serialize(serializer)
}

pub(crate) fn deserialize_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let buf = String::deserialize(deserializer)?;
    T::from_str(&buf).map_err(|e| serde::de::Error::custom(e.to_string()))
}

pub(crate) fn deserialize_from_str_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let buf = Vec::deserialize(deserializer)?;
    let mut out = vec![];
    for val in buf {
        out.push(T::from_str(val).map_err(|e| serde::de::Error::custom(e.to_string()))?);
    }
    Ok(out)
}
