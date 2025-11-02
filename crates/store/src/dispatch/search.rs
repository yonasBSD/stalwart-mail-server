/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::DocumentSet;
use crate::{
    SearchStore,
    backend::elastic::query,
    search::{IndexDocument, SearchComparator, SearchDocumentId, SearchFilter, SearchQuery},
    write::SearchIndex,
};
use trc::AddContext;
use types::collection::Collection;

impl SearchStore {
    pub async fn query<R: SearchDocumentId>(&self, query: SearchQuery) -> trc::Result<Vec<R>> {
        todo!()
        /*match self {
            SearchStore::Store(store) => {
                store
                    .index_query(account_id, collection, filters, comparators)
                    .await
            }
            #[cfg(feature = "elastic")]
            SearchStore::ElasticSearch(store) => {
                store
                    .index_query(account_id, collection, filters, comparators)
                    .await
            }
        }
        .caused_by(trc::location!())*/
    }

    pub async fn index(
        &self,
        index: SearchIndex,
        documents: Vec<IndexDocument>,
    ) -> trc::Result<()> {
        todo!()
        /*match self {
            SearchStore::Store(store) => store.index_insert(document).await,
            #[cfg(feature = "elastic")]
            SearchStore::ElasticSearch(store) => store.index_insert(document).await,
        }
        .caused_by(trc::location!())*/
    }

    pub async fn unindex(&self, query: SearchQuery) -> trc::Result<()> {
        todo!()
        /*match self {
            SearchStore::Store(store) => {
                store
                    .index_remove(account_id, collection, document_ids)
                    .await
            }
            #[cfg(feature = "elastic")]
            SearchStore::ElasticSearch(store) => {
                store
                    .index_remove(account_id, collection, document_ids)
                    .await
            }
        }
        .caused_by(trc::location!())*/
    }
}
