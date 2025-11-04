/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::mysql::MysqlStore,
    search::{IndexDocument, SearchDocumentId, SearchQuery},
    write::SearchIndex,
};

impl MysqlStore {
    pub async fn query<R: SearchDocumentId>(&self, query: SearchQuery) -> trc::Result<Vec<R>> {
        todo!()
    }

    pub async fn index(
        &self,
        index: SearchIndex,
        documents: Vec<IndexDocument>,
    ) -> trc::Result<()> {
        todo!()
    }

    pub async fn unindex(&self, query: SearchQuery) -> trc::Result<()> {
        todo!()
    }
}
