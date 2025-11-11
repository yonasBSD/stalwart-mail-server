/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::DocumentSet;
use crate::{
    Deserialize, IterateParams, Key, QueryResult, SUBSPACE_COUNTER, SUBSPACE_INDEXES,
    SUBSPACE_LOGS, Store, U32_LEN, Value, ValueKey,
    write::{
        AnyClass, AnyKey, AssignedIds, Batch, BatchBuilder, Operation, ReportClass, ValueClass,
        ValueOp,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use compact_str::ToCompactString;
use std::{ops::Range, time::Instant};
use trc::{AddContext, StoreEvent};
use types::collection::Collection;

impl Store {
    pub async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_value(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_value(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_value(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_value(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_value(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.get_value(key).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let start_time = Instant::now();
        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.iterate(params, cb).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.iterate(params, cb).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.iterate(params, cb).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.iterate(params, cb).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::DataIterate),
            Elapsed = start_time.elapsed(),
        );

        result
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_counter(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_counter(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_counter(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_counter(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_counter(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.get_counter(key).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    #[allow(unreachable_patterns)]
    #[allow(unused_variables)]
    pub async fn sql_query<T: QueryResult + std::fmt::Debug>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> trc::Result<T> {
        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.sql_query(query, &params).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.sql_query(query, &params).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.sql_query(query, &params).await,
            _ => Err(trc::StoreEvent::NotSupported.into_err()),
        };

        trc::event!(
            Store(trc::StoreEvent::SqlQuery),
            Details = query.to_compact_string(),
            Value = params.as_slice(),
            Result = &result,
        );

        result.caused_by(trc::location!())
    }

    pub async fn write(&self, batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let start_time = Instant::now();
        let ops = batch.ops.len();

        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.write(batch).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.write(batch).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.write(batch).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.write(batch).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.write(batch).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.write(batch).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        };

        trc::event!(
            Store(StoreEvent::DataWrite),
            Elapsed = start_time.elapsed(),
            Total = ops,
        );

        result
    }

    pub async fn assign_document_ids(
        &self,
        account_id: u32,
        collection: Collection,
        num_ids: u64,
    ) -> trc::Result<u32> {
        // Increment UID next
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(collection)
            .add_and_get(ValueClass::DocumentId, num_ids as i64);
        self.write(batch.build_all()).await.and_then(|v| {
            v.last_counter_id().map(|id| {
                debug_assert!(id >= num_ids as i64, "{} < {}", id, num_ids);
                id as u32
            })
        })
    }

    pub async fn purge_store(&self) -> trc::Result<()> {
        // Delete expired reports
        let now = now();
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Tls { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Tls {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Arf { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Arf {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;

        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.purge_store().await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.purge_store().await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.purge_store().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.purge_store().await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.purge_store().await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.purge_store().await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_range(from, to).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_range(from, to).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_range(from, to).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.delete_range(from, to).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_documents(
        &self,
        subspace: u8,
        account_id: u32,
        collection: u8,
        collection_offset: Option<usize>,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        // Serialize keys
        let (from_key, to_key) = if collection_offset.is_some() {
            (
                KeySerializer::new(U32_LEN + 2)
                    .write(account_id)
                    .write(collection),
                KeySerializer::new(U32_LEN + 2)
                    .write(account_id)
                    .write(collection + 1),
            )
        } else {
            (
                KeySerializer::new(U32_LEN).write(account_id),
                KeySerializer::new(U32_LEN).write(account_id + 1),
            )
        };

        // Find keys to delete
        let mut delete_keys = Vec::new();
        self.iterate(
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: from_key.finalize(),
                },
                AnyKey {
                    subspace,
                    key: to_key.finalize(),
                },
            )
            .no_values(),
            |key, _| {
                if collection_offset.is_none_or(|offset| {
                    key.get(key.len() - U32_LEN - offset).copied() == Some(collection)
                }) {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if document_ids.contains(document_id) {
                        delete_keys.push(key.to_vec());
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        // Remove keys
        let mut batch = BatchBuilder::new();

        for key in delete_keys {
            if batch.is_large_batch() {
                self.write(std::mem::take(&mut batch).build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            batch.any_op(Operation::Value {
                class: ValueClass::Any(AnyClass { subspace, key }),
                op: ValueOp::Clear,
            });
        }

        if !batch.is_empty() {
            self.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    pub async fn danger_destroy_account(&self, account_id: u32) -> trc::Result<()> {
        for subspace in [SUBSPACE_LOGS, SUBSPACE_INDEXES, SUBSPACE_COUNTER] {
            self.delete_range(
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id).finalize(),
                },
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id + 1).finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        for (from_class, to_class) in [
            (ValueClass::Acl(account_id), ValueClass::Acl(account_id + 1)),
            (ValueClass::Property(0), ValueClass::Property(0)),
        ] {
            self.delete_range(
                ValueKey {
                    account_id,
                    collection: 0,
                    document_id: 0,
                    class: from_class,
                },
                ValueKey {
                    account_id: account_id + 1,
                    collection: 0,
                    document_id: 0,
                    class: to_class,
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        Ok(())
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_blob(key, range).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_blob(key, range).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_blob(key, range).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_blob(key, range).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_blob(key, range).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.get_blob(key, range).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.put_blob(key, data).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.put_blob(key, data).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.put_blob(key, data).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.put_blob(key, data).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_blob(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_blob(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_blob(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.delete_blob(key).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    #[cfg(feature = "test_mode")]
    pub async fn destroy(&self) {
        use crate::*;

        #[cfg(any(feature = "postgres", feature = "mysql"))]
        {
            use crate::write::SearchIndex;

            for index in [
                SearchIndex::Email,
                SearchIndex::Calendar,
                SearchIndex::Contacts,
                SearchIndex::Tracing,
            ] {
                self.sql_query::<usize>(&format!("TRUNCATE TABLE {}", index.psql_table()), vec![])
                    .await
                    .unwrap();
            }
        }

        for subspace in [
            SUBSPACE_ACL,
            SUBSPACE_DIRECTORY,
            SUBSPACE_TASK_QUEUE,
            SUBSPACE_INDEXES,
            SUBSPACE_BLOB_RESERVE,
            SUBSPACE_BLOB_LINK,
            SUBSPACE_LOGS,
            SUBSPACE_IN_MEMORY_COUNTER,
            SUBSPACE_IN_MEMORY_VALUE,
            SUBSPACE_COUNTER,
            SUBSPACE_PROPERTY,
            SUBSPACE_SETTINGS,
            SUBSPACE_BLOBS,
            SUBSPACE_QUEUE_MESSAGE,
            SUBSPACE_QUEUE_EVENT,
            SUBSPACE_QUOTA,
            SUBSPACE_REPORT_OUT,
            SUBSPACE_REPORT_IN,
            SUBSPACE_TELEMETRY_SPAN,
            SUBSPACE_TELEMETRY_METRIC,
            SUBSPACE_SEARCH_INDEX,
        ] {
            if subspace == SUBSPACE_SEARCH_INDEX && self.is_pg_or_mysql() {
                continue;
            }

            self.delete_range(
                AnyKey {
                    subspace,
                    key: &[0u8],
                },
                AnyKey {
                    subspace,
                    key: &[
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                        u8::MAX,
                    ],
                },
            )
            .await
            .unwrap();
        }
    }

    #[cfg(feature = "test_mode")]
    pub async fn blob_expire_all(&self) {
        use crate::{U64_LEN, write::BlobOp};

        // Delete all temporary hashes
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: types::blob_hash::BlobHash::default(),
                until: 0,
            }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: types::blob_hash::BlobHash::default(),
                until: 0,
            }),
        };
        let mut batch = BatchBuilder::new();
        let mut last_account_id = u32::MAX;
        self.iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                let account_id = key.deserialize_be_u32(0).caused_by(trc::location!())?;
                if account_id != last_account_id {
                    last_account_id = account_id;
                    batch.with_account_id(account_id);
                }

                batch.any_op(Operation::Value {
                    class: ValueClass::Blob(BlobOp::Reserve {
                        hash: types::blob_hash::BlobHash::try_from_hash_slice(
                            key.get(U32_LEN..U32_LEN + types::blob_hash::BLOB_HASH_LEN)
                                .unwrap(),
                        )
                        .unwrap(),
                        until: key
                            .deserialize_be_u64(key.len() - U64_LEN)
                            .caused_by(trc::location!())?,
                    }),
                    op: ValueOp::Clear,
                });

                Ok(true)
            },
        )
        .await
        .unwrap();
        self.write(batch.build_all()).await.unwrap();
    }

    #[cfg(feature = "test_mode")]
    pub async fn lookup_expire_all(&self) {
        use crate::write::InMemoryClass;

        // Delete all temporary counters
        let from_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![0u8])));
        let to_key = ValueKey::from(ValueClass::InMemory(InMemoryClass::Key(vec![u8::MAX; 10])));

        let mut expired_keys = Vec::new();
        let mut expired_counters = Vec::new();

        self.iterate(IterateParams::new(from_key, to_key), |key, value| {
            let expiry = value.deserialize_be_u64(0).caused_by(trc::location!())?;
            if expiry == 0 {
                expired_counters.push(key.to_vec());
            } else if expiry != u64::MAX {
                expired_keys.push(key.to_vec());
            }
            Ok(true)
        })
        .await
        .unwrap();

        if !expired_keys.is_empty() {
            let mut batch = BatchBuilder::new();
            for key in expired_keys {
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Key(key)),
                    op: ValueOp::Clear,
                });
                if batch.is_large_batch() {
                    self.write(batch.build_all()).await.unwrap();
                    batch = BatchBuilder::new();
                }
            }
            if !batch.is_empty() {
                self.write(batch.build_all()).await.unwrap();
            }
        }

        if !expired_counters.is_empty() {
            let mut batch = BatchBuilder::new();
            for key in expired_counters {
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Counter(key.clone())),
                    op: ValueOp::Clear,
                });
                batch.any_op(Operation::Value {
                    class: ValueClass::InMemory(InMemoryClass::Key(key)),
                    op: ValueOp::Clear,
                });
                if batch.is_large_batch() {
                    self.write(batch.build_all()).await.unwrap();
                    batch = BatchBuilder::new();
                }
            }
            if !batch.is_empty() {
                self.write(batch.build_all()).await.unwrap();
            }
        }
    }

    #[cfg(feature = "test_mode")]
    #[allow(unused_variables)]
    pub async fn assert_is_empty(&self, blob_store: crate::BlobStore) {
        use crate::*;

        self.blob_expire_all().await;
        self.lookup_expire_all().await;
        self.purge_blobs(blob_store).await.unwrap();
        self.purge_store().await.unwrap();

        let store = self.clone();
        let mut failed = false;

        for (subspace, with_values) in [
            (SUBSPACE_ACL, true),
            //(SUBSPACE_DIRECTORY, true),
            (SUBSPACE_TASK_QUEUE, true),
            (SUBSPACE_IN_MEMORY_VALUE, true),
            (SUBSPACE_IN_MEMORY_COUNTER, false),
            (SUBSPACE_PROPERTY, true),
            (SUBSPACE_SETTINGS, true),
            (SUBSPACE_QUEUE_MESSAGE, true),
            (SUBSPACE_QUEUE_EVENT, true),
            (SUBSPACE_REPORT_OUT, true),
            (SUBSPACE_REPORT_IN, true),
            (SUBSPACE_BLOB_RESERVE, true),
            (SUBSPACE_BLOB_LINK, true),
            (SUBSPACE_BLOBS, true),
            (SUBSPACE_COUNTER, false),
            (SUBSPACE_QUOTA, false),
            (SUBSPACE_BLOBS, true),
            (SUBSPACE_INDEXES, false),
            (SUBSPACE_TELEMETRY_SPAN, true),
            (SUBSPACE_TELEMETRY_METRIC, true),
            (SUBSPACE_SEARCH_INDEX, true),
        ] {
            if subspace == SUBSPACE_SEARCH_INDEX && store.is_pg_or_mysql() {
                continue;
            }

            let from_key = crate::write::AnyKey {
                subspace,
                key: vec![0u8],
            };
            let to_key = crate::write::AnyKey {
                subspace,
                key: vec![u8::MAX; 10],
            };

            self.iterate(
                IterateParams::new(from_key, to_key).set_values(with_values),
                |key, value| {
                    match subspace {
                        SUBSPACE_COUNTER if key.len() == U32_LEN + 1 || key.len() == U32_LEN => {
                            // Message ID and change ID counters
                            return Ok(true);
                        }
                        SUBSPACE_INDEXES => {
                            println!(
                                concat!(
                                    "Found index key, account {}, collection {}, ",
                                    "document {}, property {}, value {:?}: {:?}"
                                ),
                                u32::from_be_bytes(key[0..4].try_into().unwrap()),
                                key[4],
                                u32::from_be_bytes(key[key.len() - 4..].try_into().unwrap()),
                                key[5],
                                String::from_utf8_lossy(&key[6..key.len() - 4]),
                                key
                            );
                        }
                        _ => {
                            println!(
                                "Found key in {:?}: {:?} ({:?}) = {:?} ({:?})",
                                char::from(subspace),
                                key,
                                String::from_utf8_lossy(key),
                                value,
                                String::from_utf8_lossy(value)
                            );
                        }
                    }
                    failed = true;

                    Ok(true)
                },
            )
            .await
            .unwrap();
        }

        // Delete logs and counters
        self.delete_range(
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: &[0u8],
            },
            AnyKey {
                subspace: SUBSPACE_LOGS,
                key: &[
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                    u8::MAX,
                ],
            },
        )
        .await
        .unwrap();

        self.delete_range(
            AnyKey {
                subspace: SUBSPACE_COUNTER,
                key: &[0u8],
            },
            AnyKey {
                subspace: SUBSPACE_COUNTER,
                key: (u32::MAX / 2).to_be_bytes().as_slice(),
            },
        )
        .await
        .unwrap();

        if failed {
            panic!("Store is not empty.");
        }
    }
}
