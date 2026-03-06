/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Core, Server,
    config::{
        server::{Listeners, tls::parse_certificates},
        storage::Storage,
        telemetry::Telemetry,
    },
    ipc::{QueueEvent, RegistryChange},
    network::security::BlockedIps,
};
use ahash::AHashMap;
use directory::Directories;
use registry::{
    schema::{prelude::ObjectType, structs::BlockedIp},
    types::error::{Error, Warning},
};
use std::sync::Arc;
use store::{LookupStores, registry::bootstrap::Bootstrap, write::now};

pub struct ReloadResult {
    pub errors: Vec<Error>,
    pub warnings: Vec<Warning>,
    pub replaced_core: bool,
}

impl Server {
    pub async fn reload_registry(&self, change: RegistryChange) -> trc::Result<ReloadResult> {
        let mut bootstrap = Bootstrap::new(self.registry().clone());
        let object = match change {
            RegistryChange::Insert(id) => {
                if matches!(id.object(), ObjectType::BlockedIp) {
                    if let Some(ip) = bootstrap.get_infallible::<BlockedIp>(id.id()).await
                        && ip.expires_at.is_none_or(|ip| ip.timestamp() > now() as i64)
                    {
                        let mut ips = self.inner.data.blocked_ips.write();
                        if let Some(ip) = ip.address.try_to_ip() {
                            ips.blocked_ip_addresses.insert(ip);
                        } else {
                            ips.blocked_ip_networks.push(ip.address);
                        }
                    }
                    return Ok(bootstrap.into());
                } else {
                    id.object()
                }
            }
            RegistryChange::Delete(id) => id.object(),
            RegistryChange::Reload(object) => object,
        };

        match object {
            ObjectType::Certificate => {
                let mut certificates = AHashMap::new();
                parse_certificates(&mut bootstrap, &mut certificates, &mut Default::default())
                    .await;
                self.inner
                    .data
                    .tls_certificates
                    .store(Arc::new(certificates));
            }
            ObjectType::MemoryLookupKey
            | ObjectType::MemoryLookupKeyValue
            | ObjectType::HttpLookup
            | ObjectType::StoreLookup => {
                let lookup = LookupStores::build(&mut bootstrap).await;

                if bootstrap.errors.is_empty() {
                    self.inner.data.lookup_stores.store(Arc::new(lookup.stores));
                }
            }

            ObjectType::BlockedIp => {
                let blocked_ips = BlockedIps::parse(&mut bootstrap).await;
                if bootstrap.errors.is_empty() {
                    *self.inner.data.blocked_ips.write() = blocked_ips;
                }
            }
            _ => {
                // Load stores
                let directory = Directories::build(&mut bootstrap).await;
                let storage = &self.core.storage;
                let storage = Storage {
                    registry: storage.registry.clone(),
                    data: storage.data.clone(),
                    blob: storage.blob.clone(),
                    search: storage.search.clone(),
                    metrics: storage.metrics.clone(),
                    tracing: storage.tracing.clone(),
                    memory: storage.memory.clone(),
                    coordinator: storage.coordinator.clone(),
                    directory: directory.default_directory,
                    directories: directory.directories,
                };

                // Parse tracers
                let tracers = Telemetry::parse(&mut bootstrap, &storage).await;

                if bootstrap.errors.is_empty() {
                    let core = Box::pin(Core::parse(&mut bootstrap, storage)).await;

                    if bootstrap.errors.is_empty() {
                        let mut servers = Listeners::parse(&mut bootstrap).await;
                        servers
                            .parse_tcp_acceptors(&mut bootstrap, self.inner.clone())
                            .await;

                        if bootstrap.errors.is_empty() {
                            // Update core
                            self.inner.shared_core.store(core.into());

                            // Update tracers

                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            tracers.update(self.inner.shared_core.load().is_enterprise_edition());
                            // SPDX-SnippetEnd
                            #[cfg(not(feature = "enterprise"))]
                            tracers.update(false);

                            // Reload queue settings
                            self.inner
                                .ipc
                                .queue_tx
                                .send(QueueEvent::ReloadSettings)
                                .await
                                .ok();

                            return Ok(ReloadResult {
                                errors: bootstrap.errors,
                                warnings: bootstrap.warnings,
                                replaced_core: true,
                            });
                        }
                    }
                }
            }
        }

        Ok(bootstrap.into())
    }
}

impl ReloadResult {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn log(&self) {
        for error in &self.errors {
            error.log();
        }
        for warning in &self.warnings {
            warning.log();
        }
    }
}

impl From<Bootstrap> for ReloadResult {
    fn from(bootstrap: Bootstrap) -> Self {
        Self {
            errors: bootstrap.errors,
            warnings: bootstrap.warnings,
            replaced_core: false,
        }
    }
}
