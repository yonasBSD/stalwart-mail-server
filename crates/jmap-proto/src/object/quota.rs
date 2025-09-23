/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::{id::Id, type_state::DataType};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuotaProperty {
    Id,
    ResourceType,
    Used,
    Name,
    Scope,
    Types,
    HardLimit,
    WarnLimit,
    SoftLimit,
    Description,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuotaValue {
    Id(Id),
    Types(DataType),
}

impl Property for QuotaProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        QuotaProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            QuotaProperty::Description => "description",
            QuotaProperty::Id => "id",
            QuotaProperty::Name => "name",
            QuotaProperty::Types => "types",
            QuotaProperty::ResourceType => "resourceType",
            QuotaProperty::Used => "used",
            QuotaProperty::HardLimit => "hardLimit",
            QuotaProperty::Scope => "scope",
            QuotaProperty::WarnLimit => "warnLimit",
            QuotaProperty::SoftLimit => "softLimit",
        }
        .into()
    }
}

impl QuotaProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => QuotaProperty::Id,
            b"resourceType" => QuotaProperty::ResourceType,
            b"used" => QuotaProperty::Used,
            b"name" => QuotaProperty::Name,
            b"scope" => QuotaProperty::Scope,
            b"types" => QuotaProperty::Types,
            b"hardLimit" => QuotaProperty::HardLimit,
            b"warnLimit" => QuotaProperty::WarnLimit,
            b"softLimit" => QuotaProperty::SoftLimit,
            b"description" => QuotaProperty::Description,
        )
    }
}

impl Element for QuotaValue {
    type Property = QuotaProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                QuotaProperty::Id => Id::from_str(value).ok().map(QuotaValue::Id),
                QuotaProperty::Types => DataType::parse(value).map(QuotaValue::Types),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            QuotaValue::Id(id) => id.to_string().into(),
            QuotaValue::Types(data_type) => data_type.as_str().into(),
        }
    }
}
