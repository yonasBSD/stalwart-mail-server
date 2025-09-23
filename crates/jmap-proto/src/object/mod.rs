/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::str::FromStr;

use jmap_tools::{Element, Property};

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
    type Property: Property;
    type Element: Element;
    type Id: FromStr;

    type Filter;
    type Comparator;

    type GetArguments;
    type SetArguments;
    type QueryArguments;
    type CopyArguments;
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
