/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Store, ValueKey, backend::MAX_TOKEN_LENGTH, search::{SearchFilter, SearchOperator, SearchQuery, SearchValue}, write::{SearchIndexClass, SearchIndexType, ValueClass}
};
use nlp::language;
use roaring::RoaringBitmap;
use trc::AddContext;
use utils::cheeky_hash::{CheekyHash, CheekyHashMap};
use std::{collections::hash_map::Entry, ops::{BitAndAssign, BitOrAssign, BitXorAssign}, sync::Arc};

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
        let mut token_cache : CheekyHashMap<Option<RoaringBitmap>> = CheekyHashMap::default();
        let account_id = None;

        while let Some(filter) = filters.next() {
            let mut result = match filter {
                SearchFilter::Operator { field, op, value } => {
                    if field.is_text() {
                        let (value, language) = match value {
                            SearchValue::Text { value, language } => (value, language),
                            _ => return Err(trc::Error::InvalidInput("Expected text value for text field".into())),
                        };

                        if op == &SearchOperator::Equal {
                            for token in language.tokenize_text(&value, MAX_TOKEN_LENGTH) {
                                let hash = CheekyHash::new(token.word.as_bytes());
                                match token_cache.entry(hash) {
                                    Entry::Occupied(entry) => {
                                        entry.get().clone()
                                    },
                                    Entry::Vacant(entry) => {
                                        let value = self.get_value::<RoaringBitmap>(ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                                            index: query.index,
                                            typ: SearchIndexType::Term { account_id, hash },
                                        }))).await.caused_by(trc::location!())?.map(Arc::new);
                                        entry.insert(value.clone());
                                        value

                                    },
                                }

                            } else {
                                todo!()
                            }

                        } else {
                    todo!()

                        }


                    } else {
                    todo!()

                    }

                }
                SearchFilter::DocumentSet(bitmap) => Some(Arc::new(bitmap)),
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
            } else if let Some(ref mut result_) = result {
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

        todo!()
    }
}
