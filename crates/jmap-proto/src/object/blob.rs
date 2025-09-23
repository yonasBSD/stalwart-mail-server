/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::object::{MaybeReference, parse_ref};
use jmap_tools::{Element, Key, Property};
use std::borrow::Cow;
use types::blob::BlobId;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobProperty {
    Id,
    BlobId,
    Type,
    Size,
    Digest(DigestProperty),
    Data(DataProperty),
    IsEncodingProblem,
    IsTruncated,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DigestProperty {
    Sha,
    Sha256,
    Sha512,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DataProperty {
    AsText,
    AsBase64,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobValue {
    BlobId(BlobId),
    IdReference(String),
}

impl Property for BlobProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        BlobProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            BlobProperty::BlobId => "blobId",
            BlobProperty::Id => "id",
            BlobProperty::Size => "size",
            BlobProperty::Type => "type",
            BlobProperty::IsEncodingProblem => "isEncodingProblem",
            BlobProperty::IsTruncated => "isTruncated",
            BlobProperty::Data(data) => match data {
                DataProperty::AsText => "data:asText",
                DataProperty::AsBase64 => "data:asBase64",
                DataProperty::Default => "data",
            },
            BlobProperty::Digest(digest) => match digest {
                DigestProperty::Sha => "digest:sha",
                DigestProperty::Sha256 => "digest:sha-256",
                DigestProperty::Sha512 => "digest:sha-512",
            },
        }
        .into()
    }
}

impl Element for BlobValue {
    type Property = BlobProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                BlobProperty::Id => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(BlobValue::Id(v)),
                    MaybeReference::Reference(v) => Some(BlobValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                BlobProperty::BlobId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(BlobValue::BlobId(v)),
                    MaybeReference::Reference(v) => Some(BlobValue::IdReference(v)),
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
            BlobValue::BlobId(blob_id) => blob_id.to_string().into(),
            BlobValue::IdReference(r) => format!("#{r}").into(),
        }
    }
}

impl BlobProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"blobId" => BlobProperty::BlobId,
            b"id" => BlobProperty::Id,
            b"size" => BlobProperty::Size,
            b"type" => BlobProperty::Type,
            b"isEncodingProblem" => BlobProperty::IsEncodingProblem,
            b"isTruncated" => BlobProperty::IsTruncated,
            b"data:asText" => BlobProperty::Data(DataProperty::AsText),
            b"data:asBase64" => BlobProperty::Data(DataProperty::AsBase64),
            b"data" => BlobProperty::Data(DataProperty::Default),
            b"digest:sha" => BlobProperty::Digest(DigestProperty::Sha),
            b"digest:sha-256" => BlobProperty::Digest(DigestProperty::Sha256),
            b"digest:sha-512" => BlobProperty::Digest(DigestProperty::Sha512),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct GetArguments {
    pub offset: Option<usize>,
    pub length: Option<usize>,
}

/*

impl RequestPropertyParser for GetArguments {
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
        match &property.hash[0] {
            0x7465_7366_666f => {
                self.offset = parser
                    .next_token::<Ignore>()?
                    .unwrap_usize_or_null("offset")?;
            }
            0x6874_676e_656c => {
                self.length = parser
                    .next_token::<Ignore>()?
                    .unwrap_usize_or_null("length")?;
            }
            _ => return Ok(false),
        }

        Ok(true)
    }
}


*/
