/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, RegistryStoreInner, Store, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    write::{
        BatchBuilder, ValueClass,
        assert::AssertValue,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use std::{path::PathBuf, time::Duration};
use trc::AddContext;
use utils::snowflake::SnowflakeIdGenerator;

const STALE_NODE_TIMEOUT: u64 = 60 * 60; // 1 hour
const DEAD_NODE_TIMEOUT: u64 = 60 * 60 * 24; // 24 hours

impl RegistryStore {
    pub async fn init(local: PathBuf) -> Result<Self, String> {
        // Create inner store
        let mut inner = RegistryStoreInner::new(local);

        // Build store
        let store = Store::build(inner.read_data_store().await?).await?;

        // Obtain node id
        let mut retry_count = 0;
        loop {
            let mut found_node_id = false;
            let mut batch = BatchBuilder::new();
            let now = now();
            let mut node_ids = Vec::new();
            store
                .iterate(
                    IterateParams::new(
                        ValueKey::from(ValueClass::NodeId(0)),
                        ValueKey::from(ValueClass::NodeId(u16::MAX)),
                    )
                    .ascending(),
                    |key, value| {
                        if key.len() == U16_LEN * 3 {
                            let node_id = key.deserialize_be_u16(U32_LEN)?;
                            let last_renewal = now.saturating_sub(value.deserialize_be_u64(0)?);
                            let hostname = value
                                .get(U64_LEN..)
                                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                .filter(|text| !text.is_empty())
                                .ok_or_else(|| trc::StoreEvent::DataCorruption.into_err())?;
                            let hash = xxhash_rust::xxh3::xxh3_64(value);

                            if hostname == inner.env_hostname || last_renewal > STALE_NODE_TIMEOUT {
                                if !found_node_id {
                                    inner.node_id = node_id;
                                    batch
                                        .assert_value(
                                            ValueClass::NodeId(node_id),
                                            AssertValue::Hash(hash),
                                        )
                                        .set(
                                            ValueClass::NodeId(node_id),
                                            KeySerializer::new(hostname.len() + U64_LEN)
                                                .write(now)
                                                .write(hostname)
                                                .finalize(),
                                        );
                                    found_node_id = true;
                                } else if last_renewal > DEAD_NODE_TIMEOUT {
                                    batch
                                        .assert_value(
                                            ValueClass::NodeId(node_id),
                                            AssertValue::Hash(hash),
                                        )
                                        .clear(ValueClass::NodeId(node_id));
                                }
                            } else {
                                node_ids.push(node_id);
                            }
                        }
                        Ok(true)
                    },
                )
                .await
                .map_err(|err| format!("Failed to iterate store: {err}"))?;

            if !found_node_id {
                if !node_ids.is_empty() {
                    node_ids.sort_unstable();
                    let mut last_node_id = 0;
                    for node_id in node_ids {
                        if node_id > last_node_id {
                            break;
                        }
                        last_node_id = node_id + 1;
                    }
                    inner.node_id = last_node_id;
                } else {
                    inner.node_id = 0;
                }

                batch
                    .assert_value(ValueClass::NodeId(inner.node_id), ())
                    .set(
                        ValueClass::NodeId(inner.node_id),
                        KeySerializer::new(inner.env_hostname.len() + U64_LEN)
                            .write(now)
                            .write(&inner.env_hostname)
                            .finalize(),
                    );
            }

            match store.write(batch.build_all()).await {
                Ok(_) => break,
                Err(err) => {
                    if err.is_assertion_failure() && retry_count < 5 {
                        retry_count += 1;
                        continue;
                    } else {
                        return Err(format!("Failed to write node id to store: {err}"));
                    }
                }
            }
        }

        inner.id_generator = SnowflakeIdGenerator::new();
        Ok(Self(inner.into()))
    }

    pub fn node_id(&self) -> u16 {
        self.0.node_id
    }

    pub fn refresh_node_id_interval(&self) -> Duration {
        Duration::from_secs(STALE_NODE_TIMEOUT / 2)
    }

    pub async fn refresh_node_id_lease(&self) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        batch
            .assert_value(ValueClass::NodeId(self.0.node_id), ())
            .set(
                ValueClass::NodeId(self.0.node_id),
                KeySerializer::new(self.0.env_hostname.len() + U64_LEN)
                    .write(now())
                    .write(&self.0.env_hostname)
                    .finalize(),
            );
        self.0
            .store
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    pub fn recovery_admin(&self) -> Option<&(String, String)> {
        self.0.env_recovery_admin.as_ref()
    }

    pub fn cluster_role(&self) -> Option<&str> {
        self.0.env_cluster_role.as_deref()
    }

    pub fn cluster_push_shard(&self) -> u32 {
        self.0.env_push_shard_id
    }

    pub fn local_hostname(&self) -> &str {
        &self.0.env_hostname
    }

    pub fn is_recovery_mode(&self) -> bool {
        self.0.env_recovery_mode
    }
}
