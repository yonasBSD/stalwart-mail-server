/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::DocumentSet;
use crate::{
    SearchStore,
    search::{IndexDocument, SearchComparator, SearchFilter},
};
use trc::AddContext;
use types::collection::Collection;

impl SearchStore {
    pub async fn index(&self, document: IndexDocument) -> trc::Result<()> {
        match self {
            SearchStore::Store(store) => store.index_insert(document).await,
            #[cfg(feature = "elastic")]
            SearchStore::ElasticSearch(store) => store.index_insert(document).await,
        }
        .caused_by(trc::location!())
    }

    pub async fn query(
        &self,
        account_id: u32,
        collection: Collection,
        filters: Vec<SearchFilter>,
        comparators: Vec<SearchComparator>,
    ) -> trc::Result<Vec<u32>> {
        match self {
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
        .caused_by(trc::location!())
    }

    pub async fn remove(
        &self,
        account_id: u32,
        collection: Collection,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        match self {
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
        .caused_by(trc::location!())
    }

    pub async fn remove_all(&self, account_id: u32) -> trc::Result<()> {
        match self {
            SearchStore::Store(store) => store.index_remove_all(account_id).await,
            #[cfg(feature = "elastic")]
            SearchStore::ElasticSearch(store) => store.index_remove_all(account_id).await,
        }
        .caused_by(trc::location!())
    }
}
