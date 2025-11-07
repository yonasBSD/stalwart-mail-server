/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Store,
    backend::MAX_TOKEN_LENGTH,
    search::{
        QueryResults, SearchComparator, SearchField, SearchFilter, SearchOperator, SearchQuery,
        SearchValue,
        bm_u32::{BitmapCache, range_to_bitmap, sort_order},
        bm_u64::{TreemapCache, range_to_treemap},
    },
};
use nlp::{language::stemmer::Stemmer, tokenizers::space::SpaceTokenizer};
use roaring::{RoaringBitmap, RoaringTreemap};
use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};
use utils::cheeky_hash::CheekyHash;

impl Store {
    pub(crate) async fn query_account(&self, query: SearchQuery) -> trc::Result<Vec<u32>> {
        struct State {
            pub op: SearchFilter,
            pub bm: Option<RoaringBitmap>,
        }
        let mut state: State = State {
            op: SearchFilter::And,
            bm: None,
        };
        let mut stack = Vec::new();
        let mask = query.mask;
        let mut filters = query.filters.into_iter().peekable();
        let mut bitmaps = BitmapCache::default();
        let mut account_id = u32::MAX;

        while let Some(filter) = filters.next() {
            let mut result = match filter {
                SearchFilter::Operator { field, op, value } => {
                    match &field {
                        SearchField::AccountId => {
                            if let SearchValue::Uint(id) = value {
                                account_id = id as u32;
                            } else {
                                return Err(trc::StoreEvent::UnexpectedError
                                    .into_err()
                                    .details("Account ID field requires uint value"));
                            }
                        }
                        SearchField::DocumentId | SearchField::Id => {
                            return Err(trc::StoreEvent::UnexpectedError
                                .into_err()
                                .details("Document ID field cannot be used in search queries"));
                        }
                        _ => {
                            if account_id == u32::MAX {
                                return Err(trc::StoreEvent::UnexpectedError
                                    .into_err()
                                    .details("Account ID must be specified before other filters"));
                            }
                        }
                    }

                    if field.is_text() {
                        let (value, language) = match value {
                            SearchValue::Text { value, language } => (value, language),
                            _ => {
                                return Err(trc::StoreEvent::UnexpectedError
                                    .into_err()
                                    .details("Expected text value for text field"));
                            }
                        };

                        if op == SearchOperator::Equal {
                            bitmaps
                                .merge_bitmaps(
                                    self,
                                    query.index,
                                    account_id,
                                    language
                                        .tokenize_text(&value, MAX_TOKEN_LENGTH)
                                        .map(|token| CheekyHash::new(token.word.as_bytes())),
                                    field.u8_id(),
                                    false,
                                )
                                .await?
                        } else {
                            let mut result = RoaringBitmap::new();
                            for token in Stemmer::new(&value, language, MAX_TOKEN_LENGTH) {
                                let hash = Some(CheekyHash::new(token.word.as_bytes()));
                                let stemmed_hash = token
                                    .stemmed_word
                                    .map(|word| CheekyHash::new(format!("{word}*")));
                                let union = bitmaps
                                    .merge_bitmaps(
                                        self,
                                        query.index,
                                        account_id,
                                        [hash, stemmed_hash].into_iter().flatten(),
                                        field.u8_id(),
                                        true,
                                    )
                                    .await?;
                                if let Some(union) = union {
                                    if result.is_empty() {
                                        result = union;
                                    } else {
                                        result.bitand_assign(&union);
                                        if result.is_empty() {
                                            break;
                                        }
                                    }
                                } else {
                                    result.clear();
                                    break;
                                }
                            }
                            if !result.is_empty() {
                                Some(result)
                            } else {
                                None
                            }
                        }
                    } else if field.is_json() {
                        let (key, value) = match value {
                            SearchValue::KeyValues(kv) => kv.into_iter().next().unwrap(),
                            _ => {
                                return Err(trc::StoreEvent::UnexpectedError
                                    .into_err()
                                    .details("Expected text value for text field"));
                            }
                        };

                        if !value.is_empty() {
                            bitmaps
                                .merge_bitmaps(
                                    self,
                                    query.index,
                                    account_id,
                                    [CheekyHash::new(format!("{key} {value}").as_bytes())]
                                        .into_iter(),
                                    field.u8_id(),
                                    false,
                                )
                                .await?
                        } else {
                            bitmaps
                                .merge_bitmaps(
                                    self,
                                    query.index,
                                    account_id,
                                    [CheekyHash::new(key.as_bytes())].into_iter(),
                                    field.u8_id(),
                                    false,
                                )
                                .await?
                        }
                    } else if field.is_indexed() {
                        let value = match value {
                            SearchValue::Text { value, .. } => value.into_bytes(),
                            SearchValue::Int(v) => (v as u64).to_be_bytes().to_vec(),
                            SearchValue::Uint(v) => v.to_be_bytes().to_vec(),
                            SearchValue::Boolean(v) => vec![v as u8],
                            SearchValue::KeyValues(_) => {
                                return Err(trc::StoreEvent::UnexpectedError
                                    .into_err()
                                    .details("Expected non key-value for non-text field"));
                            }
                        };

                        range_to_bitmap(self, query.index, account_id, field.u8_id(), &value, op)
                            .await?
                    } else {
                        return Err(trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details(format!("Field {field:?} is not indexed")));
                    }
                }
                SearchFilter::DocumentSet(bitmap) => Some(bitmap),
                op @ (SearchFilter::And | SearchFilter::Or | SearchFilter::Not) => {
                    stack.push(state);
                    state = State { op, bm: None };
                    continue;
                }
                SearchFilter::End => {
                    if let Some(prev_state) = stack.pop() {
                        let bm = state.bm;
                        state = prev_state;
                        bm
                    } else {
                        break;
                    }
                }
            };

            // Apply logical operation
            if let Some(dest) = &mut state.bm {
                match state.op {
                    SearchFilter::And => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    SearchFilter::Or => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    SearchFilter::Not => {
                        if let Some(mut result) = result {
                            result.bitxor_assign(&mask);
                            dest.bitand_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if let Some(result_) = &mut result {
                if let SearchFilter::Not = state.op {
                    result_.bitxor_assign(&mask);
                }
                state.bm = result;
            } else if let SearchFilter::Not = state.op {
                state.bm = Some(mask.clone());
            } else {
                state.bm = Some(RoaringBitmap::new());
            }

            // And short circuit
            if matches!(state.op, SearchFilter::And) && state.bm.as_ref().unwrap().is_empty() {
                while let Some(filter) = filters.peek() {
                    if matches!(filter, SearchFilter::End) {
                        break;
                    } else {
                        filters.next();
                    }
                }
            }
        }

        let mut results = state.bm.unwrap_or_default();
        results.bitand_assign(&mask);
        if results.len() > 1 && !query.comparators.is_empty() {
            let mut comparators = Vec::with_capacity(query.comparators.len());
            for comparator in query.comparators {
                let comparator = match comparator {
                    SearchComparator::Field { field, ascending } => SearchComparator::SortedSet {
                        set: sort_order(self, query.index, account_id, field.u8_id()).await?,
                        ascending,
                    },
                    _ => comparator,
                };

                comparators.push(comparator);
            }

            Ok(QueryResults::new(results, comparators).into_sorted())
        } else {
            Ok(results.into_iter().collect::<Vec<_>>())
        }
    }

    pub(crate) async fn query_global(&self, query: SearchQuery) -> trc::Result<Vec<u64>> {
        struct State {
            pub op: SearchFilter,
            pub bm: Option<RoaringTreemap>,
        }
        let mut state: State = State {
            op: SearchFilter::And,
            bm: None,
        };
        let mut stack = Vec::new();
        let mut filters = query.filters.into_iter().peekable();
        let mut bitmaps = TreemapCache::default();

        while let Some(filter) = filters.next() {
            let result = match filter {
                SearchFilter::Operator { field, op, value } => {
                    if field.is_text() {
                        let value = match value {
                            SearchValue::Text { value, .. } => value,
                            _ => {
                                return Err(trc::StoreEvent::UnexpectedError
                                    .into_err()
                                    .details("Expected text value for text field"));
                            }
                        };

                        bitmaps
                            .merge_treemaps(
                                self,
                                query.index,
                                SpaceTokenizer::new(value.as_str(), MAX_TOKEN_LENGTH)
                                    .map(|word| CheekyHash::new(word.as_bytes())),
                                field.u8_id(),
                                false,
                            )
                            .await?
                    } else if field.is_indexed() || matches!(field, SearchField::Id) {
                        let value = match value {
                            SearchValue::Text { value, .. } => value.into_bytes(),
                            SearchValue::Int(v) => (v as u64).to_be_bytes().to_vec(),
                            SearchValue::Uint(v) => v.to_be_bytes().to_vec(),
                            SearchValue::Boolean(v) => vec![v as u8],
                            SearchValue::KeyValues(_) => {
                                return Err(trc::StoreEvent::UnexpectedError
                                    .into_err()
                                    .details("Expected non key-value for non-text field"));
                            }
                        };

                        range_to_treemap(self, query.index, field.u8_id(), &value, op).await?
                    } else {
                        return Err(trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details(format!("Field {field:?} is not indexed")));
                    }
                }
                SearchFilter::DocumentSet(_) | SearchFilter::Not => {
                    return Err(trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details("Unsupported filter in global search"));
                }
                op @ (SearchFilter::And | SearchFilter::Or) => {
                    stack.push(state);
                    state = State { op, bm: None };
                    continue;
                }
                SearchFilter::End => {
                    if let Some(prev_state) = stack.pop() {
                        let bm = state.bm;
                        state = prev_state;
                        bm
                    } else {
                        break;
                    }
                }
            };

            // Apply logical operation
            if let Some(dest) = &mut state.bm {
                match state.op {
                    SearchFilter::And => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    SearchFilter::Or => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if result.is_some() {
                state.bm = result;
            } else {
                state.bm = Some(RoaringTreemap::new());
            }

            // And short circuit
            if matches!(state.op, SearchFilter::And) && state.bm.as_ref().unwrap().is_empty() {
                while let Some(filter) = filters.peek() {
                    if matches!(filter, SearchFilter::End) {
                        break;
                    } else {
                        filters.next();
                    }
                }
            }
        }

        Ok(state.bm.unwrap_or_default().into_iter().collect::<Vec<_>>())
    }
}
