/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, U64_LEN, ValueKey,
    search::*,
    write::{
        SEARCH_INDEX_MAX_FIELD_LEN, SearchIndex, SearchIndexClass, SearchIndexField, SearchIndexId,
        SearchIndexType, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use ahash::AHashMap;
use roaring::RoaringTreemap;
use std::{
    collections::hash_map::Entry,
    ops::{BitAndAssign, BitOrAssign},
};
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

#[derive(Default)]
pub(super) struct TreemapCache {
    cache: AHashMap<(CheekyHash, u8), Option<RoaringTreemap>>,
}

impl TreemapCache {
    pub async fn merge_treemaps(
        &mut self,
        store: &Store,
        index: SearchIndex,
        hashes: impl Iterator<Item = CheekyHash>,
        field: u8,
        is_union: bool,
    ) -> trc::Result<Option<RoaringTreemap>> {
        let mut result = RoaringTreemap::new();
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
                        .get_value::<RoaringTreemap>(ValueKey::from(ValueClass::SearchIndex(
                            SearchIndexClass {
                                index,
                                typ: SearchIndexType::Term {
                                    account_id: None,
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

pub(crate) async fn range_to_treemap(
    store: &Store,
    index: SearchIndex,
    field_id: u8,
    match_value: &[u8],
    op: SearchOperator,
) -> trc::Result<Option<RoaringTreemap>> {
    let ((from_value, from_id, from_field), (end_value, end_id, end_field)) = match op {
        SearchOperator::LowerThan => ((&[][..], 0, field_id), (match_value, 0, field_id)),
        SearchOperator::LowerEqualThan => {
            ((&[][..], 0, field_id), (match_value, u64::MAX, field_id))
        }
        SearchOperator::GreaterThan => (
            (match_value, u64::MAX, field_id),
            (&[][..], u64::MAX, field_id + 1),
        ),
        SearchOperator::GreaterEqualThan => (
            (match_value, 0, field_id),
            (&[][..], u64::MAX, field_id + 1),
        ),
        SearchOperator::Equal | SearchOperator::Contains => (
            (match_value, 0, field_id),
            (match_value, u64::MAX, field_id),
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
            id: SearchIndexId::Global { id: from_id },
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
            id: SearchIndexId::Global { id: end_id },
            field: SearchIndexField {
                field_id: end_field,
                len: len as u8,
                data,
            },
        },
    }));

    let mut bm = RoaringTreemap::new();
    let prefix = KeySerializer::new(U64_LEN + 2)
        .write(index.as_u8() | 1 << 6)
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

                let id_pos = key.len() - U64_LEN;
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
                    bm.insert(key.deserialize_be_u64(id_pos)?);
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
