/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityProperty {
    Id,
    Name,
    Email,
    ReplyTo,
    Bcc,
    TextSignature,
    HtmlSignature,
    MayDelete,

    // Other
    Pointer(JsonPointer<IdentityProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityValue {
    Id(Id),
}

impl Property for IdentityProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        IdentityProperty::parse(value, key.is_none())
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            IdentityProperty::Bcc => "bcc",
            IdentityProperty::Email => "email",
            IdentityProperty::HtmlSignature => "htmlSignature",
            IdentityProperty::Id => "id",
            IdentityProperty::MayDelete => "mayDelete",
            IdentityProperty::Name => "name",
            IdentityProperty::ReplyTo => "replyTo",
            IdentityProperty::TextSignature => "textSignature",
            IdentityProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
        }
        .into()
    }
}

impl Element for IdentityValue {
    type Property = IdentityProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                IdentityProperty::Id => Id::from_str(value).ok().map(IdentityValue::Id),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            IdentityValue::Id(id) => id.to_string().into(),
        }
    }
}

impl IdentityProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => IdentityProperty::Id,
            b"name" => IdentityProperty::Name,
            b"email" => IdentityProperty::Email,
            b"replyTo" => IdentityProperty::ReplyTo,
            b"bcc" => IdentityProperty::Bcc,
            b"textSignature" => IdentityProperty::TextSignature,
            b"htmlSignature" => IdentityProperty::HtmlSignature,
            b"mayDelete" => IdentityProperty::MayDelete,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                IdentityProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &IdentityProperty {
        if let IdentityProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}
