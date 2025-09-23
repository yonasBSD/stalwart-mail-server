/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use types::{id::Id, special_use::SpecialUse};

use crate::object::{MaybeReference, parse_ref};

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
                MailboxProperty::Role => SpecialUse::from_str(value).ok().map(MailboxValue::Role),
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
pub struct SetArguments {
    pub on_destroy_remove_emails: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct QueryArguments {
    pub sort_as_tree: Option<bool>,
    pub filter_as_tree: Option<bool>,
}

/*
impl RequestPropertyParser for SetArguments {
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
        if property.hash[0] == 0x4565_766f_6d65_5279_6f72_7473_6544_6e6f
            && property.hash[1] == 0x0073_6c69_616d
        {
            self.on_destroy_remove_emails = parser
                .next_token::<Ignore>()?
                .unwrap_bool_or_null("onDestroyRemoveEmails")?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl RequestPropertyParser for QueryArguments {
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
        match &property.hash[0] {
            0x6565_7254_7341_7472_6f73 => {
                self.sort_as_tree = parser
                    .next_token::<Ignore>()?
                    .unwrap_bool_or_null("sortAsTree")?;
            }
            0x6565_7254_7341_7265_746c_6966 => {
                self.filter_as_tree = parser
                    .next_token::<Ignore>()?
                    .unwrap_bool_or_null("filterAsTree")?;
            }
            _ => return Ok(false),
        }

        Ok(true)
    }
}
*/
