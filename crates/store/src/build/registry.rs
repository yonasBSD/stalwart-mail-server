/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{RegistryStore, RegistryStoreInner, Store};
use ahash::AHashSet;
use registry::schema::enums::NodeRole;
use std::path::PathBuf;
use utils::snowflake::SnowflakeIdGenerator;

impl RegistryStore {
    pub async fn init(local: PathBuf) -> Result<Self, String> {
        const ERROR_MSG: &str = "Failed to initialize registry";

        let mut inner = RegistryStoreInner::new(local);

        // Build store
        let store = Store::build(inner.read_data_store().await?).await?;

        let todo = "obtain node id";
        inner.store = store;
        inner.node_id = 0;

        if inner.node_id == 0 {
            return Err(format!(
                "{ERROR_MSG}: \"LocalSettings\" object has invalid nodeId of 0."
            ));
        }
        inner.id_generator = SnowflakeIdGenerator::new();
        Ok(Self(inner.into()))
    }

    pub fn recovery_admin(&self) -> Option<&(String, String)> {
        self.0.env_recovery_admin.as_ref()
    }

    pub fn node_roles(&self) -> &AHashSet<NodeRole> {
        &self.0.env_node_roles
    }

    pub fn node_roles_shard(&self) -> u64 {
        self.0.env_node_roles_shard_id
    }

    pub fn local_hostname(&self) -> &str {
        &self.0.env_hostname
    }
}
