/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        MaybeReference,
        email::{EmailProperty, EmailValue},
        parse_ref,
    },
    request::reference::MaybeIdReference,
    types::date::UTCDate,
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property, Value};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailSubmissionProperty {
    Id,
    IdentityId,
    ThreadId,
    Envelope,
    MailFrom,
    RcptTo,
    Email,
    Parameters,
    SendAt,
    UndoStatus,
    DeliveryStatus,
    SmtpReply,
    Delivered,
    Displayed,
    DsnBlobIds,
    MdnBlobIds,

    Pointer(JsonPointer<EmailSubmissionProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EmailSubmissionValue {
    Id(Id),
    Date(UTCDate),
    BlobId(BlobId),
    UndoStatus(UndoStatus),
    Delivered(Delivered),
    Displayed(Displayed),
    IdReference(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UndoStatus {
    Pending,
    Final,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Delivered {
    Queued,
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Displayed {
    Yes,
    Unknown,
}

impl Property for EmailSubmissionProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        EmailSubmissionProperty::from_str(value, key.is_none())
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailSubmissionProperty::DeliveryStatus => "deliveryStatus",
            EmailSubmissionProperty::DsnBlobIds => "dsnBlobIds",
            EmailSubmissionProperty::Email => "email",
            EmailSubmissionProperty::Envelope => "envelope",
            EmailSubmissionProperty::Id => "id",
            EmailSubmissionProperty::IdentityId => "identityId",
            EmailSubmissionProperty::MdnBlobIds => "mdnBlobIds",
            EmailSubmissionProperty::SendAt => "sendAt",
            EmailSubmissionProperty::ThreadId => "threadId",
            EmailSubmissionProperty::UndoStatus => "undoStatus",
            EmailSubmissionProperty::Parameters => "parameters",
            EmailSubmissionProperty::SmtpReply => "smtpReply",
            EmailSubmissionProperty::Delivered => "delivered",
            EmailSubmissionProperty::Displayed => "displayed",
            EmailSubmissionProperty::MailFrom => "mailFrom",
            EmailSubmissionProperty::RcptTo => "rcptTo",
            EmailSubmissionProperty::Pointer(json_pointer) => {
                return json_pointer.to_string().into();
            }
        }
        .into()
    }
}

impl Element for EmailSubmissionValue {
    type Property = EmailSubmissionProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                EmailSubmissionProperty::Id | EmailSubmissionProperty::ThreadId => {
                    match parse_ref(value) {
                        MaybeReference::Value(v) => Some(EmailSubmissionValue::Id(v)),
                        MaybeReference::Reference(v) => Some(EmailSubmissionValue::IdReference(v)),
                        MaybeReference::ParseError => None,
                    }
                }
                EmailSubmissionProperty::MdnBlobIds | EmailSubmissionProperty::DsnBlobIds => {
                    match parse_ref(value) {
                        MaybeReference::Value(v) => Some(EmailSubmissionValue::BlobId(v)),
                        MaybeReference::Reference(v) => Some(EmailSubmissionValue::IdReference(v)),
                        MaybeReference::ParseError => None,
                    }
                }
                EmailSubmissionProperty::SendAt => UTCDate::from_str(value)
                    .ok()
                    .map(EmailSubmissionValue::Date),
                EmailSubmissionProperty::UndoStatus => {
                    UndoStatus::parse(value).map(EmailSubmissionValue::UndoStatus)
                }
                EmailSubmissionProperty::Delivered => {
                    Delivered::parse(value).map(EmailSubmissionValue::Delivered)
                }
                EmailSubmissionProperty::Displayed => {
                    Displayed::parse(value).map(EmailSubmissionValue::Displayed)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            EmailSubmissionValue::Id(id) => id.to_string().into(),
            EmailSubmissionValue::Date(utcdate) => utcdate.to_string().into(),
            EmailSubmissionValue::BlobId(blob_id) => blob_id.to_string().into(),
            EmailSubmissionValue::IdReference(r) => format!("#{r}").into(),
            EmailSubmissionValue::UndoStatus(undo_status) => undo_status.as_str().into(),
            EmailSubmissionValue::Delivered(delivered) => delivered.as_str().into(),
            EmailSubmissionValue::Displayed(displayed) => displayed.as_str().into(),
        }
    }
}

impl EmailSubmissionProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            "id" => EmailSubmissionProperty::Id,
            "identityId" => EmailSubmissionProperty::IdentityId,
            "threadId" => EmailSubmissionProperty::ThreadId,
            "envelope" => EmailSubmissionProperty::Envelope,
            "mailFrom" => EmailSubmissionProperty::MailFrom,
            "rcptTo" => EmailSubmissionProperty::RcptTo,
            "email" => EmailSubmissionProperty::Email,
            "parameters" => EmailSubmissionProperty::Parameters,
            "sendAt" => EmailSubmissionProperty::SendAt,
            "undoStatus" => EmailSubmissionProperty::UndoStatus,
            "deliveryStatus" => EmailSubmissionProperty::DeliveryStatus,
            "smtpReply" => EmailSubmissionProperty::SmtpReply,
            "delivered" => EmailSubmissionProperty::Delivered,
            "displayed" => EmailSubmissionProperty::Displayed,
            "dsnBlobIds" => EmailSubmissionProperty::DsnBlobIds,
            "mdnBlobIds" => EmailSubmissionProperty::MdnBlobIds,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                EmailSubmissionProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &EmailSubmissionProperty {
        if let EmailSubmissionProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

impl UndoStatus {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"pending" => UndoStatus::Pending,
            b"final" => UndoStatus::Final,
            b"canceled" => UndoStatus::Canceled,
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            UndoStatus::Pending => "pending",
            UndoStatus::Final => "final",
            UndoStatus::Canceled => "canceled",
        }
    }
}

impl Delivered {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"queued" => Delivered::Queued,
            b"yes" => Delivered::Yes,
            b"no" => Delivered::No,
            b"unknown" => Delivered::Unknown,
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            Delivered::Queued => "queued",
            Delivered::Yes => "yes",
            Delivered::No => "no",
            Delivered::Unknown => "unknown",
        }
    }
}

impl Displayed {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"yes" => Displayed::Yes,
            b"unknown" => Displayed::Unknown,
        )
    }

    fn as_str(&self) -> &'static str {
        match self {
            Displayed::Yes => "yes",
            Displayed::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SetArguments<'x> {
    pub on_success_update_email:
        Option<VecMap<MaybeReference<Id>, Value<'x, EmailProperty, EmailValue>>>,
    pub on_success_destroy_email: Option<Vec<MaybeIdReference<Id>>>,
}

/*impl RequestPropertyParser for SetArguments {
    fn parse(&mut self, parser: &mut Parser, property: RequestProperty) -> trc::Result<bool> {
        if property.hash[0] == 0x4565_7461_6470_5573_7365_6363_7553_6e6f
            && property.hash[1] == 0x6c69_616d
        {
            self.on_success_update_email =
                <Option<VecMap<MaybeReference<Id, String>, Value<'x, P, E>>>>::parse(parser)?;
            Ok(true)
        } else if property.hash[0] == 0x796f_7274_7365_4473_7365_6363_7553_6e6f
            && property.hash[1] == 0x006c_6961_6d45
        {
            self.on_success_destroy_email =
                <Option<Vec<MaybeReference<Id, String>>>>::parse(parser)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
*/
