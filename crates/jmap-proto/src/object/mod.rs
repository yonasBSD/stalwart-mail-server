/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::request::deserialize::DeserializeArguments;
use jmap_tools::{Element, Property};
use serde::Serialize;
use std::str::FromStr;

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

pub trait JmapObject {
    type Property: Property + FromStr + Serialize;
    type Element: Element<Property = Self::Property> + From<Self::Id>;
    type Id: FromStr + Serialize;

    type Filter: Default + for<'de> DeserializeArguments<'de>;
    type Comparator: Default + for<'de> DeserializeArguments<'de>;

    type GetArguments: Default + for<'de> DeserializeArguments<'de>;
    type SetArguments: Default + for<'de> DeserializeArguments<'de>;
    type QueryArguments: Default + for<'de> DeserializeArguments<'de>;
    type CopyArguments: Default + for<'de> DeserializeArguments<'de>;

    const ID_PROPERTY: Self::Property;
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
