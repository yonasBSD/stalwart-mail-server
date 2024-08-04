/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use jmap_proto::types::{
    collection::Collection, id::Id, keyword::Keyword, property::Property, state::StateChange,
    type_state::DataType,
};
use store::{
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{
        log::ChangeLogBuilder, BatchBuilder, Bincode, BitmapClass, MaybeDynamicId, TagValue,
        ValueClass, F_BITMAP, F_CLEAR, F_VALUE,
    },
    BitmapKey, IterateParams, ValueKey, U32_LEN,
};
use trc::{AddContext, StoreEvent};
use utils::codec::leb128::Leb128Reader;

use crate::{
    mailbox::{UidMailbox, JUNK_ID, TOMBSTONE_ID, TRASH_ID},
    JMAP,
};

use super::{index::EmailIndexBuilder, metadata::MessageMetadata};
use rand::prelude::SliceRandom;

impl JMAP {
    pub async fn emails_tombstone(
        &self,
        account_id: u32,
        mut document_ids: RoaringBitmap,
    ) -> trc::Result<(ChangeLogBuilder, RoaringBitmap)> {
        // Create batch
        let mut changes = ChangeLogBuilder::with_change_id(0);
        let mut delete_properties = AHashMap::new();

        // Fetch mailboxes and threadIds
        let mut thread_ids: AHashMap<u32, i32> = AHashMap::new();
        for (document_id, mailboxes) in self
            .get_properties::<Vec<UidMailbox>, _, _>(
                account_id,
                Collection::Email,
                &document_ids,
                Property::MailboxIds,
            )
            .await?
        {
            delete_properties.insert(
                document_id,
                DeleteProperties {
                    mailboxes,
                    thread_id: None,
                },
            );
        }
        for (document_id, thread_id) in self
            .get_properties::<u32, _, _>(
                account_id,
                Collection::Email,
                &document_ids,
                Property::ThreadId,
            )
            .await?
        {
            *thread_ids.entry(thread_id).or_default() += 1;
            delete_properties
                .entry(document_id)
                .or_insert_with(DeleteProperties::default)
                .thread_id = Some(thread_id);
        }

        // Obtain all threadIds
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    BitmapKey {
                        account_id,
                        collection: Collection::Email.into(),
                        class: BitmapClass::Tag {
                            field: Property::ThreadId.into(),
                            value: TagValue::Id(0),
                        },
                        document_id: 0,
                    },
                    BitmapKey {
                        account_id,
                        collection: Collection::Email.into(),
                        class: BitmapClass::Tag {
                            field: Property::ThreadId.into(),
                            value: TagValue::Id(u32::MAX),
                        },
                        document_id: u32::MAX,
                    },
                )
                .no_values(),
                |key, _| {
                    let (thread_id, _) = key
                        .get(U32_LEN + 2..)
                        .and_then(|bytes| bytes.read_leb128::<u32>())
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                    if let Some(thread_count) = thread_ids.get_mut(&thread_id) {
                        *thread_count -= 1;
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        // Tombstone message and untag it from the mailboxes
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email);

        for (document_id, delete_properties) in delete_properties {
            batch.update_document(document_id);

            if !delete_properties.mailboxes.is_empty() {
                for mailbox_id in &delete_properties.mailboxes {
                    debug_assert!(mailbox_id.uid != 0);
                    changes.log_child_update(Collection::Mailbox, mailbox_id.mailbox_id);
                }

                batch.value(
                    Property::MailboxIds,
                    delete_properties.mailboxes,
                    F_VALUE | F_BITMAP | F_CLEAR,
                );
            } else {
                trc::event!(
                    Store(StoreEvent::NotFound),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Details = "Failed to fetch mailboxIds.",
                    CausedBy = trc::location!(),
                );
            }
            if let Some(thread_id) = delete_properties.thread_id {
                batch.value(Property::ThreadId, thread_id, F_VALUE | F_BITMAP | F_CLEAR);

                // Log message deletion
                changes.log_delete(Collection::Email, Id::from_parts(thread_id, document_id));

                // Log thread changes
                if thread_ids[&thread_id] < 0 {
                    changes.log_child_update(Collection::Thread, thread_id);
                }
            } else {
                trc::event!(
                    Store(StoreEvent::NotFound),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Details = "Failed to fetch threadId.",
                    CausedBy = trc::location!(),
                );
            }
            batch.tag(
                Property::MailboxIds,
                TagValue::Id(MaybeDynamicId::Static(TOMBSTONE_ID)),
                0,
            );
            document_ids.remove(document_id);

            if batch.ops.len() >= 1000 {
                self.core
                    .storage
                    .data
                    .write(batch.build())
                    .await
                    .caused_by(trc::location!())?;

                batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email);
            }
        }

        // Delete threadIds
        for (thread_id, thread_count) in thread_ids {
            if thread_count == 0 {
                batch
                    .with_collection(Collection::Thread)
                    .delete_document(thread_id);
                changes.log_delete(Collection::Thread, thread_id);
            }
        }

        if !batch.ops.is_empty() {
            self.core
                .storage
                .data
                .write(batch.build())
                .await
                .caused_by(trc::location!())?;
        }

        Ok((changes, document_ids))
    }

    pub async fn purge_accounts(&self) {
        if let Ok(Some(account_ids)) = self.get_document_ids(u32::MAX, Collection::Principal).await
        {
            let mut account_ids: Vec<u32> = account_ids.into_iter().collect();

            // Shuffle account ids
            account_ids.shuffle(&mut rand::thread_rng());

            for account_id in account_ids {
                self.purge_account(account_id).await;
            }
        }
    }

    pub async fn purge_account(&self, account_id: u32) {
        // Lock account
        match self
            .core
            .storage
            .lookup
            .counter_incr(
                format!("purge:{account_id}").into_bytes(),
                1,
                Some(3600),
                true,
            )
            .await
        {
            Ok(1) => (),
            Ok(count) => {
                trc::event!(
                    Purge(trc::PurgeEvent::PurgeActive),
                    AccountId = account_id,
                    Total = count,
                );
                return;
            }
            Err(err) => {
                trc::error!(err
                    .details("Failed to lock account.")
                    .account_id(account_id));
                return;
            }
        }

        // Auto-expunge deleted and junk messages
        if let Some(period) = self.core.jmap.mail_autoexpunge_after {
            if let Err(err) = self.emails_auto_expunge(account_id, period).await {
                trc::error!(err
                    .details("Failed to auto-expunge messages.")
                    .account_id(account_id));
            }
        }

        // Purge tombstoned messages
        if let Err(err) = self.emails_purge_tombstoned(account_id).await {
            trc::error!(err
                .details("Failed to purge tombstoned messages.")
                .account_id(account_id));
        }

        // Purge changelogs
        if let Some(history) = self.core.jmap.changes_max_history {
            if let Err(err) = self.delete_changes(account_id, history).await {
                trc::error!(err
                    .details("Failed to purge changes.")
                    .account_id(account_id));
            }
        }

        // Delete lock
        if let Err(err) = self
            .core
            .storage
            .lookup
            .counter_delete(format!("purge:{account_id}").into_bytes())
            .await
        {
            trc::error!(err.details("Failed to delete lock.").account_id(account_id));
        }
    }

    pub async fn emails_auto_expunge(&self, account_id: u32, period: Duration) -> trc::Result<()> {
        let deletion_candidates = self
            .get_tag(
                account_id,
                Collection::Email,
                Property::MailboxIds,
                TagValue::Id(TRASH_ID),
            )
            .await?
            .unwrap_or_default()
            | self
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::MailboxIds,
                    TagValue::Id(JUNK_ID),
                )
                .await?
                .unwrap_or_default();

        if deletion_candidates.is_empty() {
            return Ok(());
        }
        let reference_cid = self.inner.snowflake_id.past_id(period).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate reference cid.")
        })?;

        // Find messages to destroy
        let mut destroy_ids = RoaringBitmap::new();
        for (document_id, cid) in self
            .get_properties::<u64, _, _>(
                account_id,
                Collection::Email,
                &deletion_candidates,
                Property::Cid,
            )
            .await?
        {
            if cid < reference_cid {
                destroy_ids.insert(document_id);
            }
        }

        if destroy_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::AutoExpunge),
            AccountId = account_id,
            Total = destroy_ids.len(),
        );

        // Tombstone messages
        let (changes, _) = self.emails_tombstone(account_id, destroy_ids).await?;

        // Write and broadcast changes
        if !changes.is_empty() {
            let change_id = self.commit_changes(account_id, changes).await?;
            self.broadcast_state_change(
                StateChange::new(account_id)
                    .with_change(DataType::Email, change_id)
                    .with_change(DataType::Mailbox, change_id)
                    .with_change(DataType::Thread, change_id),
            )
            .await;
        }

        Ok(())
    }

    pub async fn emails_purge_tombstoned(&self, account_id: u32) -> trc::Result<()> {
        // Obtain tombstoned messages
        let tombstoned_ids = self
            .core
            .storage
            .data
            .get_bitmap(BitmapKey {
                account_id,
                collection: Collection::Email.into(),
                class: BitmapClass::Tag {
                    field: Property::MailboxIds.into(),
                    value: TagValue::Id(TOMBSTONE_ID),
                },
                document_id: 0,
            })
            .await?
            .unwrap_or_default();

        if tombstoned_ids.is_empty() {
            return Ok(());
        }

        trc::event!(
            Purge(trc::PurgeEvent::TombstoneCleanup),
            AccountId = account_id,
            Total = tombstoned_ids.len(),
        );

        // Delete full-text index
        self.core
            .storage
            .fts
            .remove(account_id, Collection::Email.into(), &tombstoned_ids)
            .await?;

        // Delete messages
        for document_id in tombstoned_ids {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .delete_document(document_id)
                .clear(Property::Cid)
                .tag(
                    Property::MailboxIds,
                    TagValue::Id(MaybeDynamicId::Static(TOMBSTONE_ID)),
                    F_CLEAR,
                );

            // Remove keywords
            if let Some(keywords) = self
                .core
                .storage
                .data
                .get_value::<Vec<Keyword>>(ValueKey {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                    class: ValueClass::Property(Property::Keywords.into()),
                })
                .await?
            {
                batch.value(Property::Keywords, keywords, F_VALUE | F_BITMAP | F_CLEAR);
            } else {
                trc::event!(
                    Purge(trc::PurgeEvent::Error),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Reason = "Failed to fetch keywords.",
                    CausedBy = trc::location!(),
                );
            }

            // Remove message metadata
            if let Some(metadata) = self
                .core
                .storage
                .data
                .get_value::<Bincode<MessageMetadata>>(ValueKey {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                    class: ValueClass::Property(Property::BodyStructure.into()),
                })
                .await?
            {
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL

                // Hold blob for undeletion
                #[cfg(feature = "enterprise")]
                self.core.hold_undelete(
                    &mut batch,
                    Collection::Email.into(),
                    &metadata.inner.blob_hash,
                    metadata.inner.size,
                );

                // SPDX-SnippetEnd

                // Delete message
                batch.custom(EmailIndexBuilder::clear(metadata.inner));

                // Commit batch
                self.core.storage.data.write(batch.build()).await?;
            } else {
                trc::event!(
                    Purge(trc::PurgeEvent::Error),
                    AccountId = account_id,
                    DocumentId = document_id,
                    Reason = "Failed to fetch message metadata.",
                    CausedBy = trc::location!(),
                );
            }
        }

        Ok(())
    }
}

#[derive(Default, Debug)]
struct DeleteProperties {
    mailboxes: Vec<UidMailbox>,
    thread_id: Option<u32>,
}
