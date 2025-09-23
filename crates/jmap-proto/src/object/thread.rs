/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreadProperty {
    Id,
    EmailIds,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreadValue {
    Id(Id),
}

impl Property for ThreadProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        ThreadProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ThreadProperty::Id => "id",
            ThreadProperty::EmailIds => "emailIds",
        }
        .into()
    }
}

impl Element for ThreadValue {
    type Property = ThreadProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                ThreadProperty::Id | ThreadProperty::EmailIds => {
                    Id::from_str(value).ok().map(ThreadValue::Id)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ThreadValue::Id(id) => id.to_string().into(),
        }
    }
}

impl ThreadProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ThreadProperty::Id,
            b"emailIds" => ThreadProperty::EmailIds,
        )
    }
}
