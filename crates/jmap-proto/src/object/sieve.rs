/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{DeserializeArguments, JmapObject, MaybeReference, parse_ref},
    request::reference::MaybeIdReference,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct Sieve;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SieveProperty {
    Id,
    Name,
    BlobId,
    IsActive,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SieveValue {
    Id(Id),
    BlobId(BlobId),
    IdReference(String),
}

impl Property for SieveProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        SieveProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            SieveProperty::BlobId => "blobId",
            SieveProperty::Id => "id",
            SieveProperty::Name => "name",
            SieveProperty::IsActive => "isActive",
        }
        .into()
    }
}

impl Element for SieveValue {
    type Property = SieveProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                SieveProperty::Id => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(SieveValue::Id(v)),
                    MaybeReference::Reference(v) => Some(SieveValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                SieveProperty::BlobId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(SieveValue::BlobId(v)),
                    MaybeReference::Reference(v) => Some(SieveValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            SieveValue::Id(id) => id.to_string().into(),
            SieveValue::BlobId(blob_id) => blob_id.to_string().into(),
            SieveValue::IdReference(r) => format!("#{r}").into(),
        }
    }
}

impl SieveProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => SieveProperty::Id,
            b"name" => SieveProperty::Name,
            b"blobId" => SieveProperty::BlobId,
            b"isActive" => SieveProperty::IsActive,
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct SieveSetArguments {
    pub on_success_activate_script: Option<MaybeIdReference<Id>>,
    pub on_success_deactivate_script: Option<bool>,
}

impl<'de> DeserializeArguments<'de> for SieveSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"onSuccessActivateScript" => {
                self.on_success_activate_script = map.next_value()?;
            },
            b"onSuccessDeactivateScript" => {
                self.on_success_deactivate_script = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl FromStr for SieveProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SieveProperty::parse(s).ok_or(())
    }
}

impl serde::Serialize for SieveProperty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_cow().as_ref())
    }
}

impl JmapObject for Sieve {
    type Property = SieveProperty;

    type Element = SieveValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments = SieveSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();
}
