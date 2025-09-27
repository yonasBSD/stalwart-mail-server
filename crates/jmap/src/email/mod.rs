/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::ingest::IngestedEmail;
use jmap_proto::object::email::{EmailProperty, EmailValue};
use jmap_tools::Map;
use types::id::Id;

pub mod body;
pub mod copy;
pub mod get;
pub mod headers;
pub mod import;
pub mod parse;
pub mod query;
pub mod set;
pub mod snippet;

fn ingested_into_object(email: IngestedEmail) -> Map<'static, EmailProperty, EmailValue> {
    Map::with_capacity(3)
        .with_key_value(
            EmailProperty::Id,
            Id::from_parts(email.thread_id, email.document_id),
        )
        .with_key_value(EmailProperty::ThreadId, Id::from(email.thread_id))
        .with_key_value(EmailProperty::BlobId, email.blob_id)
        .with_key_value(EmailProperty::Size, email.size)
}
