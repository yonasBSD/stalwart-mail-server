/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::ingest::IngestedEmail;
use jmap_proto::types::{
    property::Property,
    value::{Object, Value},
};
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

fn ingested_into_object(email: IngestedEmail) -> Object<Value> {
    Object::with_capacity(3)
        .with_property(
            Property::Id,
            Id::from_parts(email.thread_id, email.document_id),
        )
        .with_property(Property::ThreadId, Id::from(email.thread_id))
        .with_property(Property::BlobId, email.blob_id)
        .with_property(Property::Size, email.size)
}
