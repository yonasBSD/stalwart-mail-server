/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::cleanup::{search_store_destroy, store_assert_is_empty};
use common::Server;
use registry::schema::structs::Task;
use std::time::Duration;
use store::{
    Deserialize, IterateParams, ValueKey,
    write::{TaskQueueClass, ValueClass},
};

pub async fn wait_for_index(server: &Server) {
    let mut count = 0;
    loop {
        let mut has_index_tasks = None;
        server
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: 0 })),
                    ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Task { id: u64::MAX })),
                )
                .ascending(),
                |_, value| {
                    has_index_tasks = Some(Task::deserialize(value)?);

                    Ok(false)
                },
            )
            .await
            .unwrap();

        if let Some(task) = has_index_tasks {
            count += 1;
            if count % 10 == 0 {
                println!("Waiting for pending task {:?}...", task);
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        } else {
            break;
        }
    }
}

pub async fn assert_is_empty(server: &Server) {
    // Wait for pending index tasks
    wait_for_index(server).await;

    // Assert is empty
    store_assert_is_empty(server.store(), server.core.storage.blob.clone(), false).await;
    search_store_destroy(server.search_store()).await;

    // Clean caches
    for cache in [
        &server.inner.cache.events,
        &server.inner.cache.contacts,
        &server.inner.cache.files,
        &server.inner.cache.scheduling,
    ] {
        cache.clear();
    }
    server.inner.cache.messages.clear();
}
