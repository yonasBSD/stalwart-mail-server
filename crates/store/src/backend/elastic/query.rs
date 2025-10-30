/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::{SearchComparator, SearchFilter};

use super::{ElasticSearchStore, INDEX_NAMES, assert_success};
use elasticsearch::SearchParts;
use roaring::RoaringBitmap;
use serde_json::{Value, json};
use std::{borrow::Cow, fmt::Display};

impl ElasticSearchStore {
    pub async fn index_query(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        filters: Vec<SearchFilter>,
        comparators: Vec<SearchComparator>,
    ) -> trc::Result<Vec<u32>> {
        todo!()

        /*let mut stack: Vec<(FtsFilter<T>, Vec<Value>)> = vec![];
        let mut conditions = vec![json!({ "match": { "account_id": account_id } })];
        let mut logical_op = FtsFilter::And;

        for filter in filters {
            let is_exact = matches!(filter, FtsFilter::Exact { .. });
            match filter {
                FtsFilter::Exact { field, text, .. }
                | FtsFilter::Contains { field, text, .. }
                | FtsFilter::Keyword { field, text, .. } => {
                    let match_type = if is_exact { "term" } else { "match" };

                    if let Field::Header(name) = field {
                        conditions.push(json!({"bool": {
                          "must": [
                            {
                              "term": {
                                "header.name": name.to_string()
                              }
                            },
                            {
                                match_type: {
                                "header.value": text
                              }
                            }
                          ]
                        }}));
                    } else {
                        conditions.push(json!({
                            match_type: { field.name(): text }
                        }));
                    }
                }
                FtsFilter::And | FtsFilter::Or | FtsFilter::Not => {
                    stack.push((logical_op, conditions));
                    logical_op = filter;
                    conditions = Vec::new();
                }
                FtsFilter::End => {
                    if let Some((prev_logical_op, mut prev_conditions)) = stack.pop() {
                        if !conditions.is_empty() {
                            match logical_op {
                                FtsFilter::And => {
                                    prev_conditions.push(json!({ "bool": { "must": conditions } }));
                                }
                                FtsFilter::Or => {
                                    prev_conditions
                                        .push(json!({ "bool": { "should": conditions } }));
                                }
                                FtsFilter::Not => {
                                    prev_conditions
                                        .push(json!({ "bool": { "must_not": conditions } }));
                                }
                                _ => unreachable!(),
                            }
                        }
                        logical_op = prev_logical_op;
                        conditions = prev_conditions;
                    }
                }
            }
        }

        // TODO implement pagination
        let response = assert_success(
            self.index
                .search(SearchParts::Index(&[
                    INDEX_NAMES[collection.into() as usize]
                ]))
                .body(json!({
                    "query": {
                        "bool": {
                            "must": conditions,
                        }
                    },
                    "size": 10000,
                    "_source": ["document_id"]
                }))
                .send()
                .await,
        )
        .await?;

        let json: Value = response
            .json()
            .await
            .map_err(|err| trc::StoreEvent::ElasticsearchError.reason(err))?;
        let mut results = RoaringBitmap::new();

        for hit in json["hits"]["hits"].as_array().ok_or_else(|| {
            trc::StoreEvent::ElasticsearchError.reason("Invalid response from ElasticSearch")
        })? {
            results.insert(hit["_source"]["document_id"].as_u64().ok_or_else(|| {
                trc::StoreEvent::ElasticsearchError.reason("Invalid response from ElasticSearch")
            })? as u32);
        }

        Ok(results)*/
    }
}
