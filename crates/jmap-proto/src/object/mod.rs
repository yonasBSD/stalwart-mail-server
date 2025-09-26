/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::request::deserialize::DeserializeArguments;
use jmap_tools::{Element, Property};
use serde::Serialize;
use std::{fmt::Debug, str::FromStr};
use types::{blob::BlobId, id::Id};

pub mod blob;
pub mod email;
pub mod email_submission;
pub mod identity;
pub mod mailbox;
pub mod principal;
pub mod push_subscription;
pub mod quota;
pub mod search_snippet;
pub mod sieve;
pub mod thread;
pub mod vacation_response;

pub trait JmapObject: std::fmt::Debug {
    type Property: Property + FromStr + Serialize + Debug;
    type Element: Element<Property = Self::Property> + From<Self::Id> + JmapObjectId + Debug;
    type Id: FromStr + TryFrom<AnyId> + Serialize + Debug;

    type Filter: Default + for<'de> DeserializeArguments<'de> + Debug;
    type Comparator: Default + for<'de> DeserializeArguments<'de> + Debug;

    type GetArguments: Default + for<'de> DeserializeArguments<'de> + Debug;
    type SetArguments: Default + for<'de> DeserializeArguments<'de> + Debug;
    type QueryArguments: Default + for<'de> DeserializeArguments<'de> + Debug;
    type CopyArguments: Default + for<'de> DeserializeArguments<'de> + Debug;

    const ID_PROPERTY: Self::Property;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AnyId {
    Id(Id),
    BlobId(BlobId),
}

pub trait JmapObjectId: TryFrom<AnyId> {
    fn as_id(&self) -> Option<Id>;
    fn as_any_id(&self) -> Option<AnyId>;
    fn as_id_ref(&self) -> Option<&str>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MaybeReference<T: FromStr> {
    Value(T),
    Reference(String),
    ParseError,
}

fn parse_ref<T: FromStr>(value: &str) -> MaybeReference<T> {
    if let Some(reference) = value.strip_prefix('#') {
        MaybeReference::Reference(reference.to_string())
    } else {
        T::from_str(value)
            .map(MaybeReference::Value)
            .unwrap_or(MaybeReference::ParseError)
    }
}

impl From<Id> for AnyId {
    fn from(value: Id) -> Self {
        AnyId::Id(value)
    }
}

impl From<BlobId> for AnyId {
    fn from(value: BlobId) -> Self {
        AnyId::BlobId(value)
    }
}

impl TryFrom<AnyId> for Id {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        if let AnyId::Id(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl TryFrom<AnyId> for BlobId {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        if let AnyId::BlobId(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl<'de> serde::Deserialize<'de> for AnyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;
        if let Some(blob_id) = BlobId::from_base32(value) {
            Ok(AnyId::BlobId(blob_id))
        } else if let Ok(id) = Id::from_str(value) {
            Ok(AnyId::Id(id))
        } else {
            Err(serde::de::Error::custom(format!(
                "Invalid AnyId: {}",
                value
            )))
        }
    }
}
