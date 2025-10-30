/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use directory::{Type, backend::internal::manage::ManageDirectory};
use email::message::{index::IndexMessageText, metadata::MessageMetadata};
use std::time::Instant;
use store::{
    IterateParams, SerializeInfallible, U32_LEN, ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{BatchBuilder, BlobOp, TaskQueueClass, ValueClass, key::DeserializeBigEndian, now},
};
use trc::{AddContext, MessageIngestEvent, TaskQueueEvent};
use types::{
    blob_hash::{BLOB_HASH_LEN, BlobHash},
    collection::Collection,
    field::EmailField,
};

pub trait FtsIndexTask: Sync + Send {
    fn fts_index(
        &self,
        account_id: u32,
        document_id: u32,
        hash: &BlobHash,
    ) -> impl Future<Output = bool> + Send;
    fn fts_reindex(
        &self,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl FtsIndexTask for Server {
    async fn fts_index(&self, account_id: u32, document_id: u32, hash: &BlobHash) -> bool {
        let todo = "merge threads";
        let todo = "combine task with bayes train if needed";
        let todo = "delete Threading field on delete";

        /*loop {
            // Find messages with a matching subject
            let mut subj_results = RoaringBitmap::new();
            self.store()
                .iterate(
                    IterateParams::new(
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: 0,
                            field: EmailField::Subject.into(),
                            key: thread_name.clone(),
                        },
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: u32::MAX,
                            field: EmailField::Subject.into(),
                            key: thread_name.clone(),
                        },
                    )
                    .no_values()
                    .ascending(),
                    |key, _| {
                        let id_pos = key.len() - U32_LEN;
                        let value = key.get(IndexKeyPrefix::len()..id_pos).ok_or_else(|| {
                            trc::Error::corrupted_key(key, None, trc::location!())
                        })?;

                        if value == thread_name {
                            subj_results.insert(key.deserialize_be_u32(id_pos)?);
                        }

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;

            // No matching subjects were found, skip early
            if subj_results.is_empty() {
                return Ok(ThreadResult::Id(None));
            }

            // Find messages with matching references
            let mut results = RoaringBitmap::new();
            let mut found_message_id = Vec::new();
            self.store()
                .iterate(
                    IterateParams::new(
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: 0,
                            field: EmailField::References.into(),
                            key: references.first().unwrap().to_vec(),
                        },
                        IndexKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: u32::MAX,
                            field: EmailField::References.into(),
                            key: references.last().unwrap().to_vec(),
                        },
                    )
                    .no_values()
                    .ascending(),
                    |key, _| {
                        let id_pos = key.len() - U32_LEN;
                        let mut value =
                            key.get(IndexKeyPrefix::len()..id_pos).ok_or_else(|| {
                                trc::Error::corrupted_key(key, None, trc::location!())
                            })?;
                        let document_id = key.deserialize_be_u32(id_pos)?;

                        if let Some(message_id) = value.strip_suffix(&[0]) {
                            value = message_id;
                            if skip_duplicate.is_some_and(|(message_id, _)| message_id == value) {
                                found_message_id.push(document_id);
                            }
                        }

                        if subj_results.contains(document_id)
                            && references.binary_search(&value).is_ok()
                        {
                            results.insert(document_id);

                            if subj_results.len() == results.len() {
                                return Ok(false);
                            }
                        }

                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;

            // No matching messages
            if results.is_empty() {
                return Ok(ThreadResult::Id(None));
            }

            // Fetch cached messages
            let cache = self
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;

            // Skip duplicate messages
            if !found_message_id.is_empty()
                && cache
                    .in_mailbox(skip_duplicate.unwrap().1)
                    .any(|m| found_message_id.contains(&m.document_id))
            {
                return Ok(ThreadResult::Skip);
            }

            // Find the most common threadId
            let mut thread_counts = AHashMap::<u32, u32>::with_capacity(16);
            let mut thread_id = u32::MAX;
            let mut thread_count = 0;
            for item in &cache.emails.items {
                if results.contains(item.document_id) {
                    let tc = thread_counts.entry(item.thread_id).or_default();
                    *tc += 1;
                    if *tc > thread_count {
                        thread_count = *tc;
                        thread_id = item.thread_id;
                    }
                }
            }

            if thread_id == u32::MAX {
                return Ok(ThreadResult::Id(None));
            } else if thread_counts.len() == 1 {
                return Ok(ThreadResult::Id(Some(thread_id)));
            }

            // Delete all but the most common threadId
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Thread);
            for &delete_thread_id in thread_counts.keys() {
                if delete_thread_id != thread_id {
                    batch
                        .with_document(delete_thread_id)
                        .log_container_delete(SyncCollection::Thread);
                }
            }

            // Move messages to the new threadId
            batch.with_collection(Collection::Email);

            for item in &cache.emails.items {
                if thread_id == item.thread_id || !thread_counts.contains_key(&item.thread_id) {
                    continue;
                }
                if let Some(data_) = self
                    .archive(account_id, Collection::Email, item.document_id)
                    .await
                    .caused_by(trc::location!())?
                {
                    let data = data_
                        .to_unarchived::<MessageData>()
                        .caused_by(trc::location!())?;
                    if data.inner.thread_id != item.thread_id {
                        continue;
                    }
                    let mut new_data = data.deserialize().caused_by(trc::location!())?;
                    new_data.thread_id = thread_id;
                    batch
                        .with_document(item.document_id)
                        .custom(
                            ObjectIndexBuilder::new()
                                .with_current(data)
                                .with_changes(new_data),
                        )
                        .caused_by(trc::location!())?;
                }
            }

            match self.commit_batch(batch).await {
                Ok(_) => return Ok(ThreadResult::Id(Some(thread_id))),
                Err(err) if err.is_assertion_failure() && try_count < MAX_RETRIES => {
                    let backoff = store::rand::rng().random_range(50..=300);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    try_count += 1;
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }*/

        // Obtain raw message
        let op_start = Instant::now();
        let raw_message = if let Ok(Some(raw_message)) = self
            .blob_store()
            .get_blob(hash.as_slice(), 0..usize::MAX)
            .await
        {
            raw_message
        } else {
            trc::event!(
                TaskQueue(TaskQueueEvent::BlobNotFound),
                AccountId = account_id,
                DocumentId = document_id,
                BlobId = hash.as_slice(),
            );
            return false;
        };

        match self
            .archive_by_property(
                account_id,
                Collection::Email,
                document_id,
                EmailField::Metadata.into(),
            )
            .await
        {
            Ok(Some(metadata_)) => {
                match metadata_.unarchive::<MessageMetadata>() {
                    Ok(metadata) if metadata.blob_hash.0.as_slice() == hash.as_slice() => {
                        // Index message
                        /*let document =
                            FtsDocument::with_default_language(self.core.jmap.default_language)
                                .with_account_id(account_id)
                                .with_collection(Collection::Email)
                                .with_document_id(document_id)
                                .index_message(metadata, &raw_message);
                        if let Err(err) = self.core.storage.fts.index(document).await {
                            trc::error!(
                                err.account_id(account_id)
                                    .document_id(document_id)
                                    .details("Failed to index email in FTS index")
                            );

                            return false;
                        }*/

                        trc::event!(
                            MessageIngest(MessageIngestEvent::FtsIndex),
                            AccountId = account_id,
                            Collection = Collection::Email,
                            DocumentId = document_id,
                            Elapsed = op_start.elapsed(),
                        );
                    }
                    Err(err) => {
                        trc::error!(
                            err.account_id(account_id)
                                .document_id(document_id)
                                .details("Failed to unarchive email metadata")
                        );
                    }

                    _ => {
                        // The message was probably deleted or overwritten
                        trc::event!(
                            TaskQueue(TaskQueueEvent::MetadataNotFound),
                            Details = "E-mail blob hash mismatch",
                            AccountId = account_id,
                            DocumentId = document_id,
                        );
                    }
                }

                true
            }
            Err(err) => {
                trc::error!(
                    err.account_id(account_id)
                        .document_id(document_id)
                        .caused_by(trc::location!())
                        .details("Failed to retrieve email metadata")
                );

                false
            }
            _ => {
                // The message was probably deleted or overwritten
                trc::event!(
                    TaskQueue(TaskQueueEvent::MetadataNotFound),
                    Details = "E-mail metadata not found",
                    AccountId = account_id,
                    DocumentId = document_id,
                );
                true
            }
        }
    }

    async fn fts_reindex(
        &self,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> trc::Result<()> {
        let accounts = if let Some(account_id) = account_id {
            RoaringBitmap::from_sorted_iter([account_id]).unwrap()
        } else {
            let mut accounts = RoaringBitmap::new();
            for principal in self
                .core
                .storage
                .data
                .list_principals(
                    None,
                    tenant_id,
                    &[Type::Individual, Type::Group],
                    false,
                    0,
                    0,
                )
                .await
                .caused_by(trc::location!())?
                .items
            {
                accounts.insert(principal.id());
            }
            accounts
        };

        // Validate linked blobs
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Link {
                hash: BlobHash::default(),
            }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::Link {
                hash: BlobHash::new_max(),
            }),
        };
        let mut document_ids: AHashMap<u32, Vec<u32>> = AHashMap::new();
        self.core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                    let collection = *key
                        .get(BLOB_HASH_LEN + U32_LEN)
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                    if accounts.contains(account_id) && collection == Collection::Email as u8 {
                        document_ids
                            .entry(account_id)
                            .or_default()
                            .push(key.deserialize_be_u32(key.len() - U32_LEN)?);
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let due = now();

        for (account_id, document_ids) in document_ids {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email);

            for document_id in document_ids {
                batch.with_document(document_id).set(
                    ValueClass::TaskQueue(TaskQueueClass::IndexEmail { due }),
                    0u64.serialize(),
                );

                if batch.len() >= 2000 {
                    self.core.storage.data.write(batch.build_all()).await?;
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email);
                }
            }

            if !batch.is_empty() {
                self.core.storage.data.write(batch.build_all()).await?;
            }
        }

        // Request indexing
        self.notify_task_queue();

        Ok(())
    }
}
