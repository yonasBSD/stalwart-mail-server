/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

use crate::object::JmapObject;

#[derive(Debug, Clone, Default)]
pub struct Principal;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalProperty {
    Id,
    Type,
    Name,
    Description,
    Email,
    Timezone,
    Capabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalValue {
    Id(Id),
    Type(PrincipalType),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalType {
    Individual,
    Group,
    Resource,
    Location,
    Other,
}

impl Property for PrincipalProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        PrincipalProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PrincipalProperty::Capabilities => "capabilities",
            PrincipalProperty::Description => "description",
            PrincipalProperty::Email => "email",
            PrincipalProperty::Id => "id",
            PrincipalProperty::Name => "name",
            PrincipalProperty::Timezone => "timezone",
            PrincipalProperty::Type => "type",
        }
        .into()
    }
}

impl Element for PrincipalValue {
    type Property = PrincipalProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                PrincipalProperty::Id => Id::from_str(value).ok().map(PrincipalValue::Id),
                PrincipalProperty::Type => PrincipalType::parse(value).map(PrincipalValue::Type),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PrincipalValue::Id(id) => id.to_string().into(),
            PrincipalValue::Type(t) => t.as_str().into(),
        }
    }
}

impl PrincipalProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => PrincipalProperty::Id,
            b"type" => PrincipalProperty::Type,
            b"name" => PrincipalProperty::Name,
            b"description" => PrincipalProperty::Description,
            b"email" => PrincipalProperty::Email,
            b"timezone" => PrincipalProperty::Timezone,
            b"capabilities" => PrincipalProperty::Capabilities,
        )
    }
}

impl PrincipalType {
    pub fn parse(s: &str) -> Option<Self> {
        hashify::tiny_map!(s.as_bytes(),
            b"individual" => PrincipalType::Individual,
            b"group" => PrincipalType::Group,
            b"resource" => PrincipalType::Resource,
            b"location" => PrincipalType::Location,
            b"other" => PrincipalType::Other,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PrincipalType::Individual => "individual",
            PrincipalType::Group => "group",
            PrincipalType::Resource => "resource",
            PrincipalType::Location => "location",
            PrincipalType::Other => "other",
        }
    }
}

impl serde::Serialize for PrincipalProperty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_cow().as_ref())
    }
}

impl FromStr for PrincipalProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrincipalProperty::parse(s).ok_or(())
    }
}

impl JmapObject for Principal {
    type Property = PrincipalProperty;

    type Element = PrincipalValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments = ();

    type QueryArguments = ();

    type CopyArguments = ();
}
