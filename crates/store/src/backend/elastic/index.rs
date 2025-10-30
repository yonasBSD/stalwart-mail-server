/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ElasticSearchStore, assert_success};
use crate::{backend::elastic::INDEX_NAMES, dispatch::DocumentSet, search::IndexDocument};
use elasticsearch::{DeleteByQueryParts, IndexParts};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{borrow::Cow, fmt::Display};
use types::collection::Collection;

#[derive(Serialize, Deserialize, Default)]
struct Document<'x> {
    document_id: u32,
    account_id: u32,
    body: Vec<Cow<'x, str>>,
    attachments: Vec<Cow<'x, str>>,
    keywords: Vec<Cow<'x, str>>,
    header: Vec<Header<'x>>,
}

#[derive(Serialize, Deserialize)]
struct Header<'x> {
    name: Cow<'x, str>,
    value: Cow<'x, str>,
}

impl ElasticSearchStore {
    pub async fn index_insert(&self, document: IndexDocument) -> trc::Result<()> {
        todo!()
        /*assert_success(
            self.index
                .index(IndexParts::Index(INDEX_NAMES[document.collection as usize]))
                .body(Document::from(document))
                .send()
                .await,
        )
        .await
        .map(|_| ())*/
    }

    pub async fn index_remove(
        &self,
        account_id: u32,
        collection: Collection,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        let document_ids = document_ids.iterate().collect::<Vec<_>>();

        assert_success(
            self.index
                .delete_by_query(DeleteByQueryParts::Index(&[
                    INDEX_NAMES[collection as usize]
                ]))
                .body(json!({
                    "query": {
                        "bool": {
                            "must": [
                                { "match": { "account_id": account_id } },
                                { "terms": { "document_id": document_ids } }
                            ]
                        }
                    }
                }))
                .send()
                .await,
        )
        .await
        .map(|_| ())
    }

    pub async fn index_remove_all(&self, account_id: u32) -> trc::Result<()> {
        assert_success(
            self.index
                .delete_by_query(DeleteByQueryParts::Index(INDEX_NAMES))
                .body(json!({
                    "query": {
                        "bool": {
                            "must": [
                                { "match": { "account_id": account_id } },
                            ]
                        }
                    }
                }))
                .send()
                .await,
        )
        .await
        .map(|_| ())
    }
}
