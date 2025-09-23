/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Key, Property};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};

use crate::{
    object::{MaybeReference, parse_ref},
    request::reference::MaybeIdReference,
};

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
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
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
            match prop.patch_or_prop() {
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
pub struct SetArguments {
    pub on_success_activate_script: Option<MaybeIdReference<Id>>,
    pub on_success_deactivate_script: Option<bool>,
}

/*
impl RequestPropertyParser for SetArguments {
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
        if property.hash[0] == 0x7461_7669_7463_4173_7365_6363_7553_6e6f
            && property.hash[1] == 0x0074_7069_7263_5365
        {
            self.on_success_activate_script = parser
                .next_token::<MaybeReference<Id, String>>()?
                .unwrap_string_or_null("onSuccessActivateScript")?;
            Ok(true)
        } else if property.hash[0] == 0x7669_7463_6165_4473_7365_6363_7553_6e6f
            && property.hash[1] == 0x0074_7069_7263_5365_7461
        {
            self.on_success_deactivate_script = parser
                .next_token::<bool>()?
                .unwrap_bool_or_null("onSuccessDeactivateScript")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
*/
