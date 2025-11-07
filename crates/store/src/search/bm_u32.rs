/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, U32_LEN, ValueKey,
    search::*,
    write::{
        SEARCH_INDEX_MAX_FIELD_LEN, SearchIndex, SearchIndexClass, SearchIndexField, SearchIndexId,
        SearchIndexType, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use ahash::AHashMap;
use roaring::RoaringBitmap;
use std::{
    collections::hash_map::Entry,
    ops::{BitAndAssign, BitOrAssign},
};
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

#[derive(Default)]
pub(super) struct BitmapCache {
    cache: AHashMap<(CheekyHash, u8), Option<RoaringBitmap>>,
}

impl BitmapCache {
    pub async fn merge_bitmaps(
        &mut self,
        store: &Store,
        index: SearchIndex,
        account_id: u32,
        hashes: impl Iterator<Item = CheekyHash>,
        field: u8,
        is_union: bool,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let mut result = RoaringBitmap::new();
        for (idx, hash) in hashes.enumerate() {
            match self.cache.entry((hash, field)) {
                Entry::Occupied(entry) => {
                    if let Some(bm) = entry.get() {
                        if is_union {
                            result.bitor_assign(bm);
                        } else if idx == 0 {
                            result = bm.clone();
                        } else {
                            result.bitand_assign(bm);
                            if result.is_empty() {
                                return Ok(None);
                            }
                        }
                    } else if !is_union {
                        return Ok(None);
                    }
                }
                Entry::Vacant(entry) => {
                    let value = store
                        .get_value::<RoaringBitmap>(ValueKey::from(ValueClass::SearchIndex(
                            SearchIndexClass {
                                index,
                                typ: SearchIndexType::Term {
                                    account_id: Some(account_id),
                                    hash,
                                    field,
                                },
                            },
                        )))
                        .await
                        .caused_by(trc::location!())?;
                    if let Some(bm) = &value {
                        if is_union {
                            result.bitor_assign(bm);
                        } else if idx == 0 {
                            result = bm.clone();
                        } else {
                            result.bitand_assign(bm);
                            if result.is_empty() {
                                entry.insert(value);
                                return Ok(None);
                            }
                        }
                        entry.insert(value);
                    } else if !is_union {
                        entry.insert(None);
                        return Ok(None);
                    }
                }
            }
        }

        if !result.is_empty() {
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
}

pub(crate) async fn range_to_bitmap(
    store: &Store,
    index: SearchIndex,
    account_id: u32,
    field_id: u8,
    match_value: &[u8],
    op: SearchOperator,
) -> trc::Result<Option<RoaringBitmap>> {
    let ((from_value, from_doc_id, from_field), (end_value, end_doc_id, end_field)) = match op {
        SearchOperator::LowerThan => ((&[][..], 0, field_id), (match_value, 0, field_id)),
        SearchOperator::LowerEqualThan => {
            ((&[][..], 0, field_id), (match_value, u32::MAX, field_id))
        }
        SearchOperator::GreaterThan => (
            (match_value, u32::MAX, field_id),
            (&[][..], u32::MAX, field_id + 1),
        ),
        SearchOperator::GreaterEqualThan => (
            (match_value, 0, field_id),
            (&[][..], u32::MAX, field_id + 1),
        ),
        SearchOperator::Equal | SearchOperator::Contains => (
            (match_value, 0, field_id),
            (match_value, u32::MAX, field_id),
        ),
    };

    let len = from_value.len().min(SEARCH_INDEX_MAX_FIELD_LEN);
    let mut data = [0u8; SEARCH_INDEX_MAX_FIELD_LEN];
    if len > 0 {
        data[..len].copy_from_slice(&from_value[..len]);
    }
    let begin = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        typ: SearchIndexType::Index {
            id: SearchIndexId::Account {
                account_id,
                document_id: from_doc_id,
            },
            field: SearchIndexField {
                field_id: from_field,
                len: len as u8,
                data,
            },
        },
    }));

    let len = end_value.len().min(SEARCH_INDEX_MAX_FIELD_LEN);
    let mut data = [0u8; SEARCH_INDEX_MAX_FIELD_LEN];
    if len > 0 {
        data[..len].copy_from_slice(&end_value[..len]);
    }
    let end = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        typ: SearchIndexType::Index {
            id: SearchIndexId::Account {
                account_id,
                document_id: end_doc_id,
            },
            field: SearchIndexField {
                field_id: end_field,
                len: len as u8,
                data,
            },
        },
    }));

    let mut bm = RoaringBitmap::new();
    let prefix = KeySerializer::new(U32_LEN + 2)
        .write(index.as_u8() | 1 << 6)
        .write(account_id)
        .write(field_id)
        .finalize();
    let prefix_len = prefix.len();

    store
        .iterate(
            IterateParams::new(begin, end).no_values().ascending(),
            |key, _| {
                if !key.starts_with(&prefix) {
                    return Ok(false);
                }

                let id_pos = key.len() - U32_LEN;
                let value = key
                    .get(prefix_len..id_pos)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                let matches = match op {
                    SearchOperator::LowerThan => value < match_value,
                    SearchOperator::LowerEqualThan => value <= match_value,
                    SearchOperator::GreaterThan => value > match_value,
                    SearchOperator::GreaterEqualThan => value >= match_value,
                    SearchOperator::Equal | SearchOperator::Contains => value == match_value,
                };

                if matches {
                    bm.insert(key.deserialize_be_u32(id_pos)?);
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    if !bm.is_empty() {
        Ok(Some(bm))
    } else {
        Ok(None)
    }
}

pub(crate) async fn sort_order(
    store: &Store,
    index: SearchIndex,
    account_id: u32,
    field_id: u8,
) -> trc::Result<AHashMap<u32, u32>> {
    let begin = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        typ: SearchIndexType::Index {
            id: SearchIndexId::Account {
                account_id,
                document_id: 0,
            },
            field: SearchIndexField {
                field_id,
                len: SEARCH_INDEX_MAX_FIELD_LEN as u8,
                data: [0u8; SEARCH_INDEX_MAX_FIELD_LEN],
            },
        },
    }));
    let end = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        typ: SearchIndexType::Index {
            id: SearchIndexId::Account {
                account_id,
                document_id: u32::MAX,
            },
            field: SearchIndexField {
                field_id,
                len: SEARCH_INDEX_MAX_FIELD_LEN as u8,
                data: [u8::MAX; SEARCH_INDEX_MAX_FIELD_LEN],
            },
        },
    }));

    let mut results = AHashMap::new();
    let mut pos = 0;
    store
        .iterate(
            IterateParams::new(begin, end).no_values().ascending(),
            |key, _| {
                results.insert(key.deserialize_be_u32(key.len() - U32_LEN)?, pos);
                pos += 1;
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    Ok(results)
}
