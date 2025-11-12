/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::AddContext;

use crate::{
    SearchStore, Store,
    search::{
        IndexDocument, SearchComparator, SearchField, SearchFilter, SearchOperator, SearchQuery,
        SearchValue,
    },
    write::SearchIndex,
};
use std::cmp::Ordering;

impl SearchStore {
    pub async fn query_account(&self, query: SearchQuery) -> trc::Result<Vec<u32>> {
        // Pre-filter by mask
        match query.mask.len().cmp(&1) {
            Ordering::Equal => {
                return Ok(vec![query.mask.min().unwrap()]);
            }
            Ordering::Less => {
                return Ok(vec![]);
            }
            Ordering::Greater => {}
        }

        // If the store does not support FTS, use the internal FTS store
        if let Some(store) = self.internal_fts() {
            return store.query_account(query).await;
        }

        // If all filters and comparators are external, delegate to the underlying store
        let mut account_id = u32::MAX;
        let mut has_local_filters = false;
        for filter in &query.filters {
            match filter {
                SearchFilter::Operator {
                    field: SearchField::AccountId,
                    op: SearchOperator::Equal,
                    value: SearchValue::Uint(id),
                } => {
                    account_id = *id as u32;
                }
                SearchFilter::DocumentSet(_) => {
                    has_local_filters = true;
                }
                _ => (),
            }
        }
        if account_id == u32::MAX {
            return Err(trc::StoreEvent::UnexpectedError
                .reason("Account ID filter is required for account queries")
                .caused_by(trc::location!()));
        }

        if !has_local_filters && query.comparators.iter().all(|c| c.is_external()) {
            return self
                .sub_query(query.index, &query.filters, &query.comparators)
                .await
                .map(|results| {
                    results
                        .into_iter()
                        .filter(|id| query.mask.contains(*id))
                        .collect()
                })
                .caused_by(trc::location!());
        }

        // Decompose filters into external and local filters
        let mut filters = Vec::with_capacity(query.filters.len());
        let mut iter = query.filters.into_iter();
        let mut logical_op = None;

        while let Some(item) = iter.next() {
            match &item {
                SearchFilter::Operator {
                    field: SearchField::AccountId,
                    ..
                } => {}
                SearchFilter::Operator { .. } => {
                    let mut depth = 0;
                    let mut external = Vec::with_capacity(5);

                    // Add the logical operator if there is one
                    let in_logical_op = if let Some(op) = logical_op.take() {
                        external.push(op);
                        true
                    } else {
                        false
                    };
                    external.push(item);

                    for item in iter.by_ref() {
                        match item {
                            SearchFilter::And | SearchFilter::Or | SearchFilter::Not => {
                                depth += 1;
                                external.push(item);
                            }
                            SearchFilter::End if depth > 0 => {
                                depth -= 1;
                                external.push(item);
                            }
                            SearchFilter::Operator {
                                field: SearchField::AccountId,
                                ..
                            } => {}
                            SearchFilter::Operator { .. } => {
                                external.push(item);
                            }
                            _ => {
                                let mut new_filters = Vec::new();
                                let mut pop_count = depth;
                                while pop_count > 0 {
                                    let prev_item = external.pop().unwrap();
                                    if matches!(
                                        prev_item,
                                        SearchFilter::And | SearchFilter::Or | SearchFilter::Not
                                    ) {
                                        pop_count -= 1;
                                    }
                                    new_filters.push(prev_item);
                                }
                                let is_end = matches!(item, SearchFilter::End);
                                new_filters.push(item);

                                if !is_end {
                                    if logical_op.is_some() {
                                        depth += 1;
                                    }
                                    for item in iter {
                                        match item {
                                            SearchFilter::And
                                            | SearchFilter::Or
                                            | SearchFilter::Not => {
                                                depth += 1;
                                                new_filters.push(item);
                                            }
                                            SearchFilter::End => {
                                                depth -= 1;
                                                new_filters.push(item);
                                            }
                                            SearchFilter::Operator {
                                                field: SearchField::AccountId,
                                                ..
                                            } => {}
                                            SearchFilter::Operator { .. } if depth == 0 => {
                                                external.push(item);
                                            }
                                            _ => {
                                                new_filters.push(item);
                                            }
                                        }
                                    }
                                } else {
                                    new_filters.extend(iter);
                                }
                                iter = new_filters.into_iter();
                                break;
                            }
                        }
                    }

                    if in_logical_op {
                        external.push(SearchFilter::End);
                    }

                    // Add account id
                    if external.len() == 1 {
                        external.push(SearchFilter::Operator {
                            field: SearchField::AccountId,
                            op: SearchOperator::Equal,
                            value: SearchValue::Uint(account_id as u64),
                        });
                    } else {
                        external.insert(0, SearchFilter::And);
                        external.push(SearchFilter::Operator {
                            field: SearchField::AccountId,
                            op: SearchOperator::Equal,
                            value: SearchValue::Uint(account_id as u64),
                        });
                        external.push(SearchFilter::End);
                    }

                    // Execute sub-query
                    filters.push(SearchFilter::DocumentSet(
                        self.sub_query(query.index, &external, &[])
                            .await?
                            .into_iter()
                            .collect(),
                    ));
                }
                _ => {
                    match &item {
                        SearchFilter::Or => {
                            logical_op = Some(SearchFilter::Or);
                        }
                        SearchFilter::And | SearchFilter::Not => {
                            logical_op = Some(SearchFilter::And);
                        }
                        _ => {}
                    }
                    filters.push(item);
                }
            }
        }

        // Merge results locally
        let results = SearchQuery::new(query.index)
            .with_filters(filters)
            .with_mask(query.mask)
            .filter();

        match results.results().len().cmp(&1) {
            Ordering::Equal => Ok(vec![results.results().min().unwrap()]),
            Ordering::Less => Ok(vec![]),
            Ordering::Greater => {
                if !query.comparators.is_empty() {
                    let mut local = Vec::with_capacity(query.comparators.len());
                    let mut external = Vec::with_capacity(query.comparators.len());
                    let mut external_first = false;
                    for (pos, comparator) in query.comparators.into_iter().enumerate() {
                        if comparator.is_external() {
                            external.push(comparator);
                            if pos == 0 {
                                external_first = true;
                            }
                        } else {
                            local.push(comparator);
                        }
                    }

                    if !external.is_empty() {
                        let results = results.results();
                        let filters = vec![
                            SearchFilter::Operator {
                                field: SearchField::AccountId,
                                op: SearchOperator::Equal,
                                value: SearchValue::Uint(account_id as u64),
                            },
                            SearchFilter::Operator {
                                field: SearchField::DocumentId,
                                op: SearchOperator::GreaterEqualThan,
                                value: SearchValue::Uint(results.min().unwrap() as u64),
                            },
                            SearchFilter::Operator {
                                field: SearchField::DocumentId,
                                op: SearchOperator::LowerEqualThan,
                                value: SearchValue::Uint(results.max().unwrap() as u64),
                            },
                        ];

                        let ordered_results =
                            self.sub_query(query.index, &filters, &external).await?;

                        if local.is_empty() {
                            return Ok(ordered_results
                                .into_iter()
                                .filter(|id| results.contains(*id))
                                .collect());
                        }

                        let comparator = SearchComparator::SortedSet {
                            set: ordered_results
                                .into_iter()
                                .enumerate()
                                .map(|(pos, id)| (id, pos as u32))
                                .collect(),
                            ascending: true,
                        };

                        if external_first {
                            local.insert(0, comparator);
                        } else {
                            local.push(comparator);
                        }
                    }

                    Ok(results.with_comparators(local).into_sorted())
                } else {
                    Ok(results.results().iter().collect())
                }
            }
        }
    }

    async fn sub_query(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        sort: &[SearchComparator],
    ) -> trc::Result<Vec<u32>> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.query(index, filters, sort).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.query(index, filters, sort).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.query(index, filters, sort).await,
                // SPDX-SnippetEnd
                _ => unreachable!(),
            },
            SearchStore::ElasticSearch(store) => store.query(index, filters, sort).await,
        }
    }

    pub async fn query_global(&self, query: SearchQuery) -> trc::Result<Vec<u64>> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => {
                    store
                        .query(query.index, &query.filters, &query.comparators)
                        .await
                }
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => {
                    store
                        .query(query.index, &query.filters, &query.comparators)
                        .await
                }
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => {
                    store
                        .query(query.index, &query.filters, &query.comparators)
                        .await
                }
                // SPDX-SnippetEnd
                store => store.query_global(query).await,
            },
            SearchStore::ElasticSearch(store) => {
                store
                    .query(query.index, &query.filters, &query.comparators)
                    .await
            }
        }
    }

    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.index(documents).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.index(documents).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.index(documents).await,
                // SPDX-SnippetEnd
                store => store.index(documents).await,
            },
            SearchStore::ElasticSearch(store) => store.index(documents).await,
        }
    }

    pub async fn unindex(&self, query: SearchQuery) -> trc::Result<u64> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.unindex(query).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.unindex(query).await,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(store) => store.unindex(query).await,
                // SPDX-SnippetEnd
                store => store.unindex(query).await.map(|_| 0),
            },
            SearchStore::ElasticSearch(store) => store.unindex(query).await,
        }
    }

    pub fn internal_fts(&self) -> Option<&Store> {
        match self {
            SearchStore::Store(store) => match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(_) => None,
                #[cfg(feature = "mysql")]
                Store::MySQL(_) => None,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
                Store::SQLReadReplica(_) => None,
                // SPDX-SnippetEnd
                store => Some(store),
            },
            _ => None,
        }
    }
}

impl SearchFilter {
    pub fn is_external(&self) -> bool {
        matches!(self, SearchFilter::Operator { .. })
    }
}

impl SearchComparator {
    pub fn is_external(&self) -> bool {
        matches!(self, SearchComparator::Field { .. })
    }
}
