/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, str::FromStr};

use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use types::{id::Id, special_use::SpecialUse};

use crate::{
    object::{JmapObject, MaybeReference, parse_ref},
    request::deserialize::DeserializeArguments,
};

#[derive(Debug, Clone, Default)]
pub struct Mailbox;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailboxProperty {
    Id,
    Name,
    ParentId,
    Role,
    SortOrder,
    TotalEmails,
    UnreadEmails,
    TotalThreads,
    UnreadThreads,
    ShareWith,
    MyRights,
    MayReadItems,
    MayAddItems,
    MayRemoveItems,
    MaySetSeen,
    MaySetKeywords,
    MayCreateChild,
    MayRename,
    MaySubmit,
    IsSubscribed,

    // Other
    Pointer(JsonPointer<MailboxProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailboxValue {
    Id(Id),
    IdReference(String),
    Role(SpecialUse),
}

impl Property for MailboxProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        MailboxProperty::parse(value, key.is_none())
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MailboxProperty::Id => "id",
            MailboxProperty::IsSubscribed => "isSubscribed",
            MailboxProperty::MyRights => "myRights",
            MailboxProperty::Name => "name",
            MailboxProperty::ParentId => "parentId",
            MailboxProperty::Role => "role",
            MailboxProperty::SortOrder => "sortOrder",
            MailboxProperty::TotalEmails => "totalEmails",
            MailboxProperty::TotalThreads => "totalThreads",
            MailboxProperty::UnreadEmails => "unreadEmails",
            MailboxProperty::UnreadThreads => "unreadThreads",
            MailboxProperty::MayReadItems => "mayReadItems",
            MailboxProperty::MayAddItems => "mayAddItems",
            MailboxProperty::MayRemoveItems => "mayRemoveItems",
            MailboxProperty::MaySetSeen => "maySetSeen",
            MailboxProperty::MaySetKeywords => "maySetKeywords",
            MailboxProperty::MayCreateChild => "mayCreateChild",
            MailboxProperty::MayRename => "mayRename",
            MailboxProperty::MaySubmit => "maySubmit",
            MailboxProperty::ShareWith => "shareWith",
            MailboxProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
        }
        .into()
    }
}

impl Element for MailboxValue {
    type Property = MailboxProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                MailboxProperty::Id | MailboxProperty::ParentId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(MailboxValue::Id(v)),
                    MaybeReference::Reference(v) => Some(MailboxValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                MailboxProperty::Role => SpecialUse::parse(value).map(MailboxValue::Role),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            MailboxValue::Id(id) => id.to_string().into(),
            MailboxValue::IdReference(r) => format!("#{r}").into(),
            MailboxValue::Role(special_use) => special_use.as_str().unwrap_or_default().into(),
        }
    }
}

impl MailboxProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => MailboxProperty::Id,
            b"name" => MailboxProperty::Name,
            b"parentId" => MailboxProperty::ParentId,
            b"role" => MailboxProperty::Role,
            b"sortOrder" => MailboxProperty::SortOrder,
            b"totalEmails" => MailboxProperty::TotalEmails,
            b"unreadEmails" => MailboxProperty::UnreadEmails,
            b"totalThreads" => MailboxProperty::TotalThreads,
            b"unreadThreads" => MailboxProperty::UnreadThreads,
            b"shareWith" => MailboxProperty::ShareWith,
            b"myRights" => MailboxProperty::MyRights,
            b"mayReadItems" => MailboxProperty::MayReadItems,
            b"mayAddItems" => MailboxProperty::MayAddItems,
            b"mayRemoveItems" => MailboxProperty::MayRemoveItems,
            b"maySetSeen" => MailboxProperty::MaySetSeen,
            b"maySetKeywords" => MailboxProperty::MaySetKeywords,
            b"mayCreateChild" => MailboxProperty::MayCreateChild,
            b"mayRename" => MailboxProperty::MayRename,
            b"maySubmit" => MailboxProperty::MaySubmit,
            b"isSubscribed" => MailboxProperty::IsSubscribed,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                MailboxProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &MailboxProperty {
        if let MailboxProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MailboxSetArguments {
    pub on_destroy_remove_emails: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct MailboxQueryArguments {
    pub sort_as_tree: Option<bool>,
    pub filter_as_tree: Option<bool>,
}

impl<'de> DeserializeArguments<'de> for MailboxSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "onDestroyRemoveEmails" {
            self.on_destroy_remove_emails = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for MailboxQueryArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"sortAsTree" => {
                self.sort_as_tree = map.next_value()?;
            },
            b"filterAsTree" => {
                self.filter_as_tree = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl FromStr for MailboxProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MailboxProperty::parse(s, false).ok_or(())
    }
}

impl serde::Serialize for MailboxProperty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_cow().as_ref())
    }
}

impl JmapObject for Mailbox {
    type Property = MailboxProperty;

    type Element = MailboxValue;

    type Id = Id;

    type Filter = MailboxFilter;

    type Comparator = MailboxComparator;

    type GetArguments = ();

    type SetArguments = MailboxSetArguments;

    type QueryArguments = MailboxQueryArguments;

    type CopyArguments = ();

    const ID_PROPERTY: Self::Property = MailboxProperty::Id;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxFilter {
    Name(String),
    ParentId(Option<Id>),
    Role(Option<SpecialUse>),
    HasAnyRole(bool),
    IsSubscribed(bool),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxComparator {
    SortOrder,
    Name,
    ParentId,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for MailboxFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"name" => {
                *self = MailboxFilter::Name(map.next_value()?);
            },
            b"parentId" => {
                *self = MailboxFilter::ParentId(map.next_value()?);
            },
            b"role" => {
                *self = MailboxFilter::Role(map.next_value::<Option<RoleWrapper>>()?.map(|r| r.0));
            },
            b"hasAnyRole" => {
                *self = MailboxFilter::HasAnyRole(map.next_value()?);
            },
            b"isSubscribed" => {
                *self = MailboxFilter::IsSubscribed(map.next_value()?);
            },
            _ => {
                *self = MailboxFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for MailboxComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"sortOrder" => {
                    *self = MailboxComparator::SortOrder;
                },
                b"name" => {
                    *self = MailboxComparator::Name;
                },
                b"parentId" => {
                    *self = MailboxComparator::ParentId;
                },
                _ => {
                    *self = MailboxComparator::_T(key.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl Default for MailboxFilter {
    fn default() -> Self {
        MailboxFilter::_T("".to_string())
    }
}

impl Default for MailboxComparator {
    fn default() -> Self {
        MailboxComparator::_T("".to_string())
    }
}

struct RoleWrapper(SpecialUse);

impl<'de> serde::Deserialize<'de> for RoleWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        SpecialUse::parse(<&str>::deserialize(deserializer)?)
            .map(RoleWrapper)
            .ok_or_else(|| serde::de::Error::custom("invalid JMAP role"))
    }
}

impl From<Id> for MailboxValue {
    fn from(id: Id) -> Self {
        MailboxValue::Id(id)
    }
}
