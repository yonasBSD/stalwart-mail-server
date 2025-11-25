/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BlobOp, Operation, ValueClass, ValueOp, key::DeserializeBigEndian, now};
use crate::{
    BlobStore, IterateParams, Store, U32_LEN, U64_LEN, ValueKey,
    write::{BatchBuilder, BlobLink},
};
use trc::AddContext;
use types::{
    blob::BlobClass,
    blob_hash::{BLOB_HASH_LEN, BlobHash},
};

#[derive(Debug, PartialEq, Eq)]
pub struct BlobQuota {
    pub bytes: usize,
    pub count: usize,
}

impl Store {
    pub async fn blob_exists(&self, hash: impl AsRef<BlobHash> + Sync + Send) -> trc::Result<bool> {
        self.get_value::<()>(ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Commit {
                hash: hash.as_ref().clone(),
            }),
        })
        .await
        .map(|v| v.is_some())
        .caused_by(trc::location!())
    }

    pub async fn blob_quota(&self, account_id: u32) -> trc::Result<BlobQuota> {
        let from_key = ValueKey {
            account_id,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Quota {
                hash: BlobHash::default(),
                until: 0,
            }),
        };
        let to_key = ValueKey {
            account_id: account_id + 1,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Quota {
                hash: BlobHash::default(),
                until: u64::MAX,
            }),
        };

        let now = now();
        let mut quota = BlobQuota { bytes: 0, count: 0 };

        self.iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let until = key.deserialize_be_u64(key.len() - U64_LEN)?;
                if until > now {
                    let bytes = value.deserialize_be_u32(0)?;
                    if bytes > 0 {
                        quota.bytes += bytes as usize;
                        quota.count += 1;
                    }
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(quota)
    }

    pub async fn blob_has_access(
        &self,
        hash: impl AsRef<BlobHash> + Sync + Send,
        class: impl AsRef<BlobClass> + Sync + Send,
    ) -> trc::Result<bool> {
        let key = match class.as_ref() {
            BlobClass::Reserved {
                account_id,
                expires,
            } if *expires > now() => ValueKey {
                account_id: *account_id,
                collection: 0,
                document_id: 0,
                class: ValueClass::Blob(BlobOp::Link {
                    hash: hash.as_ref().clone(),
                    to: BlobLink::Temporary { until: *expires },
                }),
            },
            BlobClass::Linked {
                account_id,
                collection,
                document_id,
            } => ValueKey {
                account_id: *account_id,
                collection: *collection,
                document_id: *document_id,
                class: ValueClass::Blob(BlobOp::Link {
                    hash: hash.as_ref().clone(),
                    to: BlobLink::Document,
                }),
            },
            _ => return Ok(false),
        };

        self.get_value::<()>(key).await.map(|v| v.is_some())
    }

    pub async fn purge_blobs(&self, blob_store: BlobStore) -> trc::Result<()> {
        // Validate linked blobs
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Commit {
                hash: BlobHash::default(),
            }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::Link {
                hash: BlobHash::new_max(),
                to: BlobLink::Document,
            }),
        };
        const TEMP_LINK: usize = BLOB_HASH_LEN + U32_LEN + U64_LEN;
        const DOC_LINK: usize = BLOB_HASH_LEN + U64_LEN + 1;

        let mut last_hash = BlobHash::default();
        let mut last_hash_is_linked = true; // Avoid deleting non-existing last_hash on first iteration
        let mut delete_keys = Vec::new();
        let now = now();
        self.iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                let hash = BlobHash::try_from_hash_slice(
                    key.get(0..BLOB_HASH_LEN)
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?,
                )
                .unwrap();

                if last_hash != hash {
                    if !last_hash_is_linked {
                        delete_keys.push((
                            None,
                            BlobOp::Commit {
                                hash: std::mem::replace(&mut last_hash, hash),
                            },
                        ));
                    } else {
                        last_hash = hash;
                    }
                    last_hash_is_linked = false;
                }

                match key.len() {
                    BLOB_HASH_LEN => {
                        // Main blob entry
                    }
                    TEMP_LINK => {
                        // Temporary link
                        let until = key.deserialize_be_u64(BLOB_HASH_LEN + U32_LEN)?;
                        if until <= now {
                            let account_id = key.deserialize_be_u32(BLOB_HASH_LEN)?;
                            delete_keys.push((
                                Some(account_id),
                                BlobOp::Link {
                                    hash: last_hash.clone(),
                                    to: BlobLink::Temporary { until },
                                },
                            ));
                            if account_id != u32::MAX {
                                delete_keys.push((
                                    Some(account_id),
                                    BlobOp::Quota {
                                        hash: last_hash.clone(),
                                        until,
                                    },
                                ));
                                delete_keys.push((
                                    Some(account_id),
                                    BlobOp::Undelete {
                                        hash: last_hash.clone(),
                                        until,
                                    },
                                ));
                            }
                        } else {
                            last_hash_is_linked = true;
                        }
                    }
                    DOC_LINK => {
                        // Document link
                        last_hash_is_linked = true;
                    }
                    _ => {
                        return Err(trc::Error::corrupted_key(key, None, trc::location!()));
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        if !last_hash_is_linked {
            delete_keys.push((None, BlobOp::Commit { hash: last_hash }));
        }

        // Delete expired or unlinked blobs
        for (_, op) in &delete_keys {
            if let BlobOp::Commit { hash } = op {
                blob_store
                    .delete_blob(hash.as_ref())
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        // Delete hashes
        let mut batch = BatchBuilder::new();
        for (account_id, op) in delete_keys {
            if batch.is_large_batch() {
                self.write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
            }

            if let Some(account_id) = account_id {
                batch.with_account_id(account_id);
            }

            batch.any_op(Operation::Value {
                class: ValueClass::Blob(op),
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
}
