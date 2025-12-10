/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    IterateParams, SUBSPACE_TASK_QUEUE, U32_LEN, U64_LEN, ValueKey,
    write::{AnyClass, BatchBuilder, ValueClass, key::KeySerializer},
};
use trc::AddContext;

pub(crate) async fn migrate_tasks_v014(server: &Server) -> trc::Result<()> {
    let from_key = ValueKey::<ValueClass> {
        account_id: 0,
        collection: 0,
        document_id: 0,
        class: ValueClass::Any(AnyClass {
            subspace: SUBSPACE_TASK_QUEUE,
            key: KeySerializer::new(U64_LEN).write(0u64).finalize(),
        }),
    };
    let to_key = ValueKey::<ValueClass> {
        account_id: u32::MAX,
        collection: u8::MAX,
        document_id: u32::MAX,
        class: ValueClass::Any(AnyClass {
            subspace: SUBSPACE_TASK_QUEUE,
            key: KeySerializer::new(U64_LEN).write(u64::MAX).finalize(),
        }),
    };

    let mut delete_tasks = Vec::new();
    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                match key.get(U64_LEN + U32_LEN) {
                    Some(0..=2) => {
                        delete_tasks.push(key.to_vec());
                    }
                    None => {
                        return Err(trc::Error::corrupted_key(key, None, trc::location!()));
                    }
                    _ => {}
                };
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    if !delete_tasks.is_empty() {
        let num_migrated = delete_tasks.len();
        let mut batch = BatchBuilder::new();
        for key in delete_tasks {
            batch.clear(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_TASK_QUEUE,
                key,
            }));
        }
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {num_migrated} tasks")
        );
    }

    Ok(())
}
