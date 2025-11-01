/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::{IndexAction, Task};
use common::Server;
use directory::{Type, backend::internal::manage::ManageDirectory};
use groupware::cache::GroupwareCache;
use store::{
    IterateParams, SerializeInfallible, U32_LEN, ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{
        BatchBuilder, BlobOp, SearchIndex, TaskQueueClass, ValueClass, key::DeserializeBigEndian,
        now,
    },
};
use trc::AddContext;
use types::{
    blob_hash::{BLOB_HASH_LEN, BlobHash},
    collection::{Collection, SyncCollection},
};

pub(crate) trait SearchIndexTask: Sync + Send {
    fn index(&self, tasks: &[Task<IndexAction>]) -> impl Future<Output = bool> + Send;
}

pub trait ReindexIndexTask: Sync + Send {
    fn reindex(
        &self,
        index: SearchIndex,
        account_id: Option<u32>,
        tenant_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl SearchIndexTask for Server {
    async fn index(&self, tasks: &[Task<IndexAction>]) -> bool {
        todo!()
        // Obtain raw message
        /*let op_start = Instant::now();
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
        }*/
    }
}

impl ReindexIndexTask for Server {
    async fn reindex(
        &self,
        index: SearchIndex,
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
        let due = now();

        match index {
            SearchIndex::Email => {
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
                            let collection =
                                *key.get(BLOB_HASH_LEN + U32_LEN).ok_or_else(|| {
                                    trc::Error::corrupted_key(key, None, trc::location!())
                                })?;

                            if accounts.contains(account_id)
                                && collection == Collection::Email as u8
                            {
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

                for (account_id, document_ids) in document_ids {
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email);

                    for document_id in document_ids {
                        batch.with_document(document_id).set(
                            ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                                due,
                                index: SearchIndex::Email,
                                is_insert: true,
                            }),
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
            }
            SearchIndex::Calendar | SearchIndex::Contacts => {
                for account_id in accounts {
                    let Some(cache) = self.cached_dav_resources(
                        account_id,
                        if index == SearchIndex::Calendar {
                            SyncCollection::Calendar
                        } else {
                            SyncCollection::AddressBook
                        },
                    ) else {
                        continue;
                    };
                    let mut batch = BatchBuilder::new();
                    batch.with_account_id(account_id);

                    for document_id in cache.document_ids(false) {
                        batch.with_document(document_id).set(
                            ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                                due,
                                index,
                                is_insert: true,
                            }),
                            0u64.serialize(),
                        );

                        if batch.len() >= 2000 {
                            self.core.storage.data.write(batch.build_all()).await?;
                            batch = BatchBuilder::new();
                            batch.with_account_id(account_id);
                        }
                    }

                    if !batch.is_empty() {
                        self.core.storage.data.write(batch.build_all()).await?;
                    }
                }
            }
            SearchIndex::File | SearchIndex::TracingSpan | SearchIndex::InMemory => (),
        }

        // Request indexing
        self.notify_task_queue();

        Ok(())
    }
}
