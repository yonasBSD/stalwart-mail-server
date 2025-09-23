/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::method::MethodName;
use jmap_tools::{JsonPointer, Null};
use std::{fmt::Display, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResultReference {
    #[serde(rename = "resultOf")]
    pub result_of: String,
    pub name: MethodName,
    pub path: JsonPointer<Null>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeIdReference<V: FromStr> {
    Id(V),
    Reference(String),
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeResultReference<V> {
    Value(V),
    Reference(ResultReference),
}

impl Display for ResultReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ resultOf: {}, name: {}, path: {} }}",
            self.result_of, self.name, self.path
        )
    }
}

impl<V: FromStr + Display> Display for MaybeIdReference<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaybeIdReference::Id(id) => write!(f, "{}", id),
            MaybeIdReference::Reference(str) => write!(f, "#{}", str),
            MaybeIdReference::Invalid(str) => write!(f, "{}", str),
        }
    }
}

impl<'de, V: FromStr> serde::Deserialize<'de> for MaybeIdReference<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;

        if let Some(reference) = value.strip_prefix('#') {
            if reference.is_empty() {
                return Ok(MaybeIdReference::Invalid(value.to_string()));
            }
            Ok(MaybeIdReference::Reference(reference.to_string()))
        } else if let Ok(id) = V::from_str(value) {
            Ok(MaybeIdReference::Id(id))
        } else {
            Ok(MaybeIdReference::Invalid(value.to_string()))
        }
    }
}

impl serde::Serialize for MaybeIdReference<Id> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            MaybeIdReference::Id(id) => id.serialize(serializer),
            MaybeIdReference::Reference(str) => serializer.serialize_str(&format!("#{}", str)),
            MaybeIdReference::Invalid(str) => serializer.serialize_str(str),
        }
    }
}
