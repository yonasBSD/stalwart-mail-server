/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::get_document_ids;
use common::Server;
use store::write::BatchBuilder;
use trc::AddContext;
use types::{collection::Collection, field::IdentityField};

pub(crate) async fn migrate_identities_v014(server: &Server, account_id: u32) -> trc::Result<u64> {
    let identity_ids = get_document_ids(server, account_id, Collection::Identity)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_identities = identity_ids.len();
    if num_identities == 0 {
        return Ok(0);
    }

    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);

    for document_id in identity_ids {
        batch
            .with_document(document_id)
            .tag(IdentityField::DocumentId);
    }

    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    Ok(num_identities as u64)
}
