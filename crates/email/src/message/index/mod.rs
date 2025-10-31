/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::metadata::{ArchivedMessageData, MessageData};
use common::storage::index::{IndexValue, IndexableObject};
use types::{blob_hash::BlobHash, collection::SyncCollection};

pub mod extractors;
pub mod metadata;
pub mod search;

pub(super) const MAX_MESSAGE_PARTS: usize = 1000;
pub const PREVIEW_LENGTH: usize = 256;

impl IndexableObject for MessageData {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogItem {
                sync_collection: SyncCollection::Email,
                prefix: self.thread_id.into(),
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Thread,
                ids: vec![self.thread_id],
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Email,
                ids: self.mailboxes.iter().map(|m| m.mailbox_id).collect(),
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedMessageData {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::LogItem {
                sync_collection: SyncCollection::Email,
                prefix: self.thread_id.to_native().into(),
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Thread,
                ids: vec![self.thread_id.to_native()],
            },
            IndexValue::LogContainerProperty {
                sync_collection: SyncCollection::Email,
                ids: self
                    .mailboxes
                    .iter()
                    .map(|m| m.mailbox_id.to_native())
                    .collect(),
            },
        ]
        .into_iter()
    }
}

pub(super) trait IndexMessage {
    #[allow(clippy::too_many_arguments)]
    fn index_message(
        &mut self,
        account_id: u32,
        tenant_id: Option<u32>,
        message: mail_parser::Message<'_>,
        blob_hash: BlobHash,
        data: MessageData,
        received_at: u64,
    ) -> trc::Result<&mut Self>;
}
