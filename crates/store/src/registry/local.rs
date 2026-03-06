/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use registry::{
    schema::{enums::NodeRole, structs::DataStore},
    types::EnumImpl,
};
use std::path::PathBuf;
use utils::snowflake::SnowflakeIdGenerator;

impl RegistryStoreInner {
    pub(crate) fn new(local_path: PathBuf) -> Self {
        Self {
            local_path,
            store: Store::None,
            id_generator: SnowflakeIdGenerator::new(),
            node_id: 0,
            env_recovery_admin: std::env::var("STALWART_RECOVERY_ACCOUNT")
                .ok()
                .filter(|a| !a.is_empty())
                .and_then(|a| {
                    std::env::var("STALWART_RECOVERY_PASS")
                        .ok()
                        .filter(|p| !p.is_empty())
                        .map(|p| (a, p))
                }),
            env_node_roles: std::env::var("STALWART_ROLES")
                .ok()
                .map(|roles| {
                    roles
                        .split(',')
                        .map(|r| r.trim())
                        .filter(|r| !r.is_empty())
                        .filter_map(|r| {
                            let role = NodeRole::parse(r);
                            if role.is_none() {
                                eprintln!(
                                    "Invalid node role specified in STALWART_NODE_ROLES: {r}"
                                );
                            }
                            role
                        })
                        .collect()
                })
                .unwrap_or_default(),
            env_node_roles_shard_id: std::env::var("STALWART_ROLES_SHARD")
                .ok()
                .and_then(|id| id.parse::<u64>().ok())
                .unwrap_or(1),
            env_hostname: std::env::var("STALWART_HOSTNAME")
                .ok()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned()),
        }
    }

    pub(crate) async fn read_data_store(&self) -> Result<DataStore, String> {
        tokio::fs::read_to_string(&self.local_path)
            .await
            .map_err(|err| {
                format!(
                    "Failed to read data store settings at {}: {}",
                    self.local_path.display(),
                    err
                )
            })
            .and_then(|contents| {
                serde_json::from_str::<DataStore>(&contents).map_err(|err| {
                    format!(
                        "Failed to parse data store settings at {}: {}",
                        self.local_path.display(),
                        err
                    )
                })
            })
    }
}

impl RegistryStore {
    pub async fn write_data_store(&self, data_store: &DataStore) -> trc::Result<()> {
        let json_text = serde_json::to_string(data_store).map_err(|err| {
            trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                .into_err()
                .caused_by(trc::location!())
                .reason(err)
        })?;
        tokio::fs::write(&self.0.local_path, json_text)
            .await
            .map_err(|err| {
                trc::EventType::Registry(trc::RegistryEvent::LocalWriteError)
                    .into_err()
                    .caused_by(trc::location!())
                    .reason(err)
            })
    }
}
