/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{JmapObject, MaybeReference, parse_ref},
    request::{MaybeInvalid, deserialize::DeserializeArguments},
    types::date::UTCDate,
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use mail_parser::HeaderName;
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::{blob::BlobId, id::Id, keyword::Keyword};

#[derive(Debug, Clone, Default)]
pub struct Email;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailProperty {
    // Metadata
    Id,
    BlobId,
    ThreadId,
    MailboxIds,
    Keywords,
    Size,
    ReceivedAt,

    // Address
    Name,
    Email,

    // GroupedAddresses
    Addresses,

    // Header Fields Properties
    Value,
    Header(HeaderProperty),

    // Convenience properties
    MessageId,
    InReplyTo,
    References,
    Sender,
    From,
    To,
    Cc,
    Bcc,
    ReplyTo,
    Subject,
    SentAt,

    // Body Parts
    TextBody,
    HtmlBody,
    Attachments,
    PartId,
    Headers,
    Type,
    Charset,
    Disposition,
    Cid,
    Language,
    Location,
    SubParts,
    BodyStructure,
    BodyValues,
    IsEncodingProblem,
    IsTruncated,
    HasAttachment,
    Preview,

    // Other
    Keyword(Keyword),
    Pointer(JsonPointer<EmailProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeaderProperty {
    pub form: HeaderForm,
    pub header: String,
    pub all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeaderForm {
    Raw,
    Text,
    Addresses,
    GroupedAddresses,
    MessageIds,
    Date,
    URLs,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailValue {
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    IdReference(String),
}

impl Property for EmailProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        let allow_patch = key.is_none();
        if let Some(Key::Property(key)) = key {
            match key.patch_or_prop() {
                EmailProperty::Keywords => EmailProperty::Keyword(Keyword::parse(value)).into(),
                _ => EmailProperty::parse(value, allow_patch),
            }
        } else {
            EmailProperty::parse(value, allow_patch)
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailProperty::Attachments => "attachments",
            EmailProperty::Bcc => "bcc",
            EmailProperty::BlobId => "blobId",
            EmailProperty::BodyStructure => "bodyStructure",
            EmailProperty::BodyValues => "bodyValues",
            EmailProperty::Cc => "cc",
            EmailProperty::Charset => "charset",
            EmailProperty::Cid => "cid",
            EmailProperty::Disposition => "disposition",
            EmailProperty::Email => "email",
            EmailProperty::From => "from",
            EmailProperty::HasAttachment => "hasAttachment",
            EmailProperty::Headers => "headers",
            EmailProperty::HtmlBody => "htmlBody",
            EmailProperty::Id => "id",
            EmailProperty::InReplyTo => "inReplyTo",
            EmailProperty::Keywords => "keywords",
            EmailProperty::Language => "language",
            EmailProperty::Location => "location",
            EmailProperty::MailboxIds => "mailboxIds",
            EmailProperty::MessageId => "messageId",
            EmailProperty::Name => "name",
            EmailProperty::PartId => "partId",
            EmailProperty::Preview => "preview",
            EmailProperty::ReceivedAt => "receivedAt",
            EmailProperty::References => "references",
            EmailProperty::ReplyTo => "replyTo",
            EmailProperty::Sender => "sender",
            EmailProperty::SentAt => "sentAt",
            EmailProperty::Size => "size",
            EmailProperty::Subject => "subject",
            EmailProperty::SubParts => "subParts",
            EmailProperty::TextBody => "textBody",
            EmailProperty::ThreadId => "threadId",
            EmailProperty::To => "to",
            EmailProperty::Type => "type",
            EmailProperty::Addresses => "addresses",
            EmailProperty::Value => "value",
            EmailProperty::IsEncodingProblem => "isEncodingProblem",
            EmailProperty::IsTruncated => "isTruncated",
            EmailProperty::Header(header) => return header.to_string().into(),
            EmailProperty::Keyword(keyword) => return keyword.to_string().into(),
            EmailProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
        }
        .into()
    }
}

impl Element for EmailValue {
    type Property = EmailProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                EmailProperty::Id | EmailProperty::ThreadId | EmailProperty::MailboxIds => {
                    match parse_ref(value) {
                        MaybeReference::Value(v) => Some(EmailValue::Id(v)),
                        MaybeReference::Reference(v) => Some(EmailValue::IdReference(v)),
                        MaybeReference::ParseError => None,
                    }
                }
                EmailProperty::BlobId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(EmailValue::BlobId(v)),
                    MaybeReference::Reference(v) => Some(EmailValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                EmailProperty::Header(HeaderProperty {
                    form: HeaderForm::Date,
                    ..
                })
                | EmailProperty::ReceivedAt
                | EmailProperty::SentAt => UTCDate::from_str(value).ok().map(EmailValue::Date),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailValue::Id(id) => id.to_string().into(),
            EmailValue::Date(utcdate) => utcdate.to_string().into(),
            EmailValue::BlobId(blob_id) => blob_id.to_string().into(),
            EmailValue::IdReference(r) => format!("#{r}").into(),
        }
    }
}

impl EmailProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
                "id" => EmailProperty::Id,
                "blobId" => EmailProperty::BlobId,
                "threadId" => EmailProperty::ThreadId,
                "mailboxIds" => EmailProperty::MailboxIds,
                "keywords" => EmailProperty::Keywords,
                "size" => EmailProperty::Size,
                "receivedAt" => EmailProperty::ReceivedAt,
                "name" => EmailProperty::Name,
                "email" => EmailProperty::Email,
                "addresses" => EmailProperty::Addresses,
                "value" => EmailProperty::Value,
                "messageId" => EmailProperty::MessageId,
                "inReplyTo" => EmailProperty::InReplyTo,
                "references" => EmailProperty::References,
                "sender" => EmailProperty::Sender,
                "from" => EmailProperty::From,
                "to" => EmailProperty::To,
                "cc" => EmailProperty::Cc,
                "bcc" => EmailProperty::Bcc,
                "replyTo" => EmailProperty::ReplyTo,
                "subject" => EmailProperty::Subject,
                "sentAt" => EmailProperty::SentAt,
                "textBody" => EmailProperty::TextBody,
                "htmlBody" => EmailProperty::HtmlBody,
                "attachments" => EmailProperty::Attachments,
                "partId" => EmailProperty::PartId,
                "headers" => EmailProperty::Headers,
                "type" => EmailProperty::Type,
                "charset" => EmailProperty::Charset,
                "disposition" => EmailProperty::Disposition,
                "cid" => EmailProperty::Cid,
                "language" => EmailProperty::Language,
                "location" => EmailProperty::Location,
                "subParts" => EmailProperty::SubParts,
                "bodyStructure" => EmailProperty::BodyStructure,
                "bodyValues" => EmailProperty::BodyValues,
                "isEncodingProblem" => EmailProperty::IsEncodingProblem,
                "isTruncated" => EmailProperty::IsTruncated,
                "hasAttachment" => EmailProperty::HasAttachment,
                "preview" => EmailProperty::Preview
        )
        .or_else(|| {
            if let Some(header) = value.strip_prefix("header:") {
                HeaderProperty::parse(header).map(EmailProperty::Header)
            } else if allow_patch && value.contains('/') {
                EmailProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &EmailProperty {
        if let EmailProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }

    pub fn as_rfc_header(&self) -> HeaderName<'static> {
        match self {
            EmailProperty::MessageId => HeaderName::MessageId,
            EmailProperty::InReplyTo => HeaderName::InReplyTo,
            EmailProperty::References => HeaderName::References,
            EmailProperty::Sender => HeaderName::Sender,
            EmailProperty::From => HeaderName::From,
            EmailProperty::To => HeaderName::To,
            EmailProperty::Cc => HeaderName::Cc,
            EmailProperty::Bcc => HeaderName::Bcc,
            EmailProperty::ReplyTo => HeaderName::ReplyTo,
            EmailProperty::Subject => HeaderName::Subject,
            EmailProperty::SentAt => HeaderName::Date,
            _ => unreachable!(),
        }
    }
}

impl HeaderProperty {
    fn parse(value: &str) -> Option<Self> {
        let mut result = HeaderProperty {
            form: HeaderForm::Raw,
            header: String::new(),
            all: false,
        };

        for (pos, value) in value.split(':').enumerate() {
            match pos {
                0 => {
                    result.header = value.to_string();
                }
                1 => {
                    hashify::fnc_map!(value.as_bytes(),
                        b"asText" => { result.form = HeaderForm::Text;},
                        b"asAddresses" => { result.form = HeaderForm::Addresses;},
                        b"asGroupedAddresses" => { result.form = HeaderForm::GroupedAddresses;},
                        b"asMessageIds" => { result.form = HeaderForm::MessageIds;},
                        b"asDate" => { result.form = HeaderForm::Date;},
                        b"asURLs" => { result.form = HeaderForm::URLs;},
                        b"asRaw"  => { result.form = HeaderForm::Raw; },
                        b"all"  => { result.all = true; },
                        _ => {
                            return None;
                        }
                    );
                }
                2 if value == "all" && result.all == false => {
                    result.all = true;
                }
                _ => return None,
            }
        }

        if !result.header.is_empty() {
            Some(result)
        } else {
            None
        }
    }
}

impl Display for HeaderProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "header:{}", self.header)?;
        self.form.fmt(f)?;
        if self.all { write!(f, ":all") } else { Ok(()) }
    }
}

impl Display for HeaderForm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HeaderForm::Raw => Ok(()),
            HeaderForm::Text => write!(f, ":asText"),
            HeaderForm::Addresses => write!(f, ":asAddresses"),
            HeaderForm::GroupedAddresses => write!(f, ":asGroupedAddresses"),
            HeaderForm::MessageIds => write!(f, ":asMessageIds"),
            HeaderForm::Date => write!(f, ":asDate"),
            HeaderForm::URLs => write!(f, ":asURLs"),
        }
    }
}

impl FromStr for EmailProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EmailProperty::parse(s, false).ok_or(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct EmailGetArguments {
    pub body_properties: Option<Vec<MaybeInvalid<EmailProperty>>>,
    pub fetch_text_body_values: Option<bool>,
    pub fetch_html_body_values: Option<bool>,
    pub fetch_all_body_values: Option<bool>,
    pub max_body_value_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct EmailQueryArguments {
    pub collapse_threads: Option<bool>,
}

impl<'de> DeserializeArguments<'de> for EmailGetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"bodyProperties" => {
                self.body_properties = map.next_value()?;
            },
            b"fetchTextBodyValues" => {
                self.fetch_text_body_values = map.next_value()?;
            },
            b"fetchHTMLBodyValues" => {
                self.fetch_html_body_values = map.next_value()?;
            },
            b"fetchAllBodyValues" => {
                self.fetch_all_body_values = map.next_value()?;
            },
            b"maxBodyValueBytes" => {
                self.max_body_value_bytes = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for EmailQueryArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "collapseThreads" {
            self.collapse_threads = map.next_value()?;
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }

        Ok(())
    }
}

impl serde::Serialize for EmailProperty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_cow().as_ref())
    }
}

impl JmapObject for Email {
    type Property = EmailProperty;

    type Element = EmailValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = EmailGetArguments;

    type SetArguments = ();

    type QueryArguments = ();

    type CopyArguments = ();
}
