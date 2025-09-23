/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::types::date::UTCDate;
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VacationResponseProperty {
    Id,
    IsEnabled,
    FromDate,
    ToDate,
    TextBody,
    HtmlBody,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VacationResponseValue {
    Id(Id),
    Date(UTCDate),
}

impl Property for VacationResponseProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        VacationResponseProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            VacationResponseProperty::HtmlBody => "htmlBody",
            VacationResponseProperty::Id => "id",
            VacationResponseProperty::TextBody => "textBody",
            VacationResponseProperty::FromDate => "fromDate",
            VacationResponseProperty::IsEnabled => "isEnabled",
            VacationResponseProperty::ToDate => "toDate",
        }
        .into()
    }
}

impl Element for VacationResponseValue {
    type Property = VacationResponseProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                VacationResponseProperty::Id => {
                    Id::from_str(value).ok().map(VacationResponseValue::Id)
                }
                VacationResponseProperty::FromDate | VacationResponseProperty::ToDate => {
                    UTCDate::from_str(value)
                        .ok()
                        .map(VacationResponseValue::Date)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            VacationResponseValue::Id(id) => id.to_string().into(),
            VacationResponseValue::Date(utcdate) => utcdate.to_string().into(),
            VacationResponseValue::BlobId(blob_id) => blob_id.to_string().into(),
            VacationResponseValue::IdReference(r) => format!("#{r}").into(),
        }
    }
}

impl VacationResponseProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => VacationResponseProperty::Id,
            b"isEnabled" => VacationResponseProperty::IsEnabled,
            b"fromDate" => VacationResponseProperty::FromDate,
            b"toDate" => VacationResponseProperty::ToDate,
            b"textBody" => VacationResponseProperty::TextBody,
            b"htmlBody" => VacationResponseProperty::HtmlBody,
        )
    }
}
