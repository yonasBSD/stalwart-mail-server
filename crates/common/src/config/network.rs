/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::{
    expr::if_block::{BootstrapExprExt, IfBlock},
    network::security::Security,
};
use ahash::AHashMap;
use registry::{
    schema::{
        prelude::ObjectType,
        structs::{self, Asn, HttpForm, Rate, SystemSettings, TaskManager},
    },
    types::EnumImpl,
};
use std::{hash::Hasher, str::FromStr, time::Duration};
use xxhash_rust::xxh3::Xxh3Builder;

#[derive(Clone)]
pub struct Network {
    pub node_id: u64,
    pub roles: ClusterRoles,
    pub server_name: String,
    pub security: Security,
    pub http: Http,
    pub contact_form: Option<ContactForm>,
    pub asn_geo_lookup: AsnGeoLookupConfig,
    pub task_manager: TaskManager,
}

#[derive(Clone)]
pub struct Http {
    pub rate_authenticated: Option<Rate>,
    pub rate_anonymous: Option<Rate>,
    pub response_url: IfBlock,
    pub allowed_endpoint: IfBlock,
    pub response_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    pub use_forwarded: bool,
}

#[derive(Clone)]
pub struct ContactForm {
    pub rcpt_to: Vec<String>,
    pub max_size: usize,
    pub rate: Option<Rate>,
    pub validate_domain: bool,
    pub from_email: FieldOrDefault,
    pub from_subject: FieldOrDefault,
    pub from_name: FieldOrDefault,
    pub field_honey_pot: Option<String>,
}

#[derive(Clone, Default)]
pub struct ClusterRoles {
    pub store_maintenance: ClusterRole,
    pub account_maintenance: ClusterRole,
    pub push_notifications: ClusterRole,
    pub search_indexing: ClusterRole,
    pub spam_training: ClusterRole,
    pub imip_processing: ClusterRole,
    pub merge_threads: ClusterRole,
    pub calendar_alerts: ClusterRole,
    pub dns_acme: ClusterRole,
    pub calculate_metrics: ClusterRole,
    pub push_metrics: ClusterRole,
    pub outbound_mta: ClusterRole,
    pub task_scheduler: ClusterRole,
    pub task_manager: ClusterRole,
}

#[derive(Clone, Copy, Default)]
pub enum ClusterRole {
    #[default]
    Enabled,
    Disabled,
    Sharded {
        shard_id: u32,
        total_shards: u32,
    },
}

#[derive(Clone, Default)]
pub enum AsnGeoLookupConfig {
    Resource {
        expires: Duration,
        timeout: Duration,
        max_size: usize,
        headers: HeaderMap,
        asn_resources: Vec<String>,
        geo_resources: Vec<String>,
    },
    Dns {
        zone_ipv4: String,
        zone_ipv6: String,
        separator: String,
        index_asn: usize,
        index_asn_name: Option<usize>,
        index_country: Option<usize>,
    },
    #[default]
    Disabled,
}

#[derive(Clone)]
pub struct FieldOrDefault {
    pub field: Option<String>,
    pub default: String,
}

impl ContactForm {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        let form = bp.setting_infallible::<HttpForm>().await;

        if !form.enable {
            return None;
        } else if form.deliver_to.is_empty() {
            bp.build_error(
                ObjectType::HttpForm.singleton(),
                "Contact form is enabled but no recipient addresses are configured",
            );
            return None;
        }

        Some(ContactForm {
            rcpt_to: form.deliver_to.into_inner(),
            max_size: form.max_size as usize,
            validate_domain: form.validate_domain,
            from_email: FieldOrDefault {
                field: form.field_email,
                default: form.default_from_address,
            },
            from_subject: FieldOrDefault {
                field: form.field_subject,
                default: form.default_subject,
            },
            from_name: FieldOrDefault {
                field: form.field_name,
                default: form.default_name,
            },
            field_honey_pot: form.field_honey_pot,
            rate: form.rate_limit,
        })
    }
}

impl Network {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let system = bp.setting_infallible::<SystemSettings>().await;

        let mut network = Network {
            node_id: bp.node_id(),
            server_name: system.default_hostname,
            security: Security::parse(bp).await,
            contact_form: ContactForm::parse(bp).await,
            asn_geo_lookup: AsnGeoLookupConfig::parse(bp).await.unwrap_or_default(),
            roles: ClusterRoles::default(),
            http: Http::parse(bp).await,
            task_manager: bp.setting_infallible::<TaskManager>().await,
        };

        // Process ranges
        let node_id = bp.node_id();
        let ranges = bp.list_infallible::<NodeRole>().await;
        if !ranges.is_empty() {
            for network_role in network.roles.all_mut() {
                network_role.set_uninit();
            }

            for range in ranges {
                let is_success = match &range.object {
                    NodeRole::CalculateMetrics(_)
                    | NodeRole::PushMetrics(_)
                    | NodeRole::SpamClassifierTraining(_)
                    | NodeRole::TaskScheduler(_) => {
                        let (roles, role_obj) = match &range.object {
                            NodeRole::CalculateMetrics(role) => {
                                (&mut network.roles.calculate_metrics, role)
                            }
                            NodeRole::PushMetrics(role) => (&mut network.roles.push_metrics, role),
                            NodeRole::SpamClassifierTraining(role) => {
                                (&mut network.roles.spam_training, role)
                            }
                            NodeRole::TaskScheduler(role) => {
                                (&mut network.roles.task_scheduler, role)
                            }
                            _ => unreachable!(),
                        };

                        roles.set_role(role_obj.node_id == node_id)
                    }
                    NodeRole::StoreMaintenance(_)
                    | NodeRole::AccountMaintenance(_)
                    | NodeRole::PushNotifications(_)
                    | NodeRole::SearchIndexing(_)
                    | NodeRole::ImipProcessing(_)
                    | NodeRole::CalendarAlerts(_)
                    | NodeRole::MergeThreads(_)
                    | NodeRole::DnsAndAcme(_)
                    | NodeRole::OutboundMta(_)
                    | NodeRole::TaskQueueProcessing(_) => {
                        let (roles, role_obj) = match &range.object {
                            NodeRole::StoreMaintenance(role) => {
                                (&mut network.roles.store_maintenance, role)
                            }
                            NodeRole::AccountMaintenance(role) => {
                                (&mut network.roles.account_maintenance, role)
                            }
                            NodeRole::PushNotifications(role) => {
                                (&mut network.roles.push_notifications, role)
                            }
                            NodeRole::SearchIndexing(role) => {
                                (&mut network.roles.search_indexing, role)
                            }
                            NodeRole::ImipProcessing(role) => {
                                (&mut network.roles.imip_processing, role)
                            }
                            NodeRole::CalendarAlerts(role) => {
                                (&mut network.roles.calendar_alerts, role)
                            }
                            NodeRole::MergeThreads(role) => {
                                (&mut network.roles.merge_threads, role)
                            }
                            NodeRole::OutboundMta(role) => (&mut network.roles.outbound_mta, role),
                            NodeRole::DnsAndAcme(role) => (&mut network.roles.dns_acme, role),
                            NodeRole::TaskQueueProcessing(role) => {
                                (&mut network.roles.task_manager, role)
                            }
                            _ => unreachable!(),
                        };

                        roles.set_role(
                            role_obj
                                .node_ranges
                                .values()
                                .any(|range| range.contains(node_id)),
                        )
                    }
                };

                if !is_success {
                    bp.build_warning(
                        range.id,
                        format!("Multiple role definitions found for node id {node_id}",),
                    );
                }
            }

            for network_role in network.roles.all_mut() {
                network_role.finalize();
            }

            // Node shards
            let mut shards = AHashMap::new();
            for shard in bp.list_infallible::<NodeShard>().await {
                shards
                    .entry(shard.object.shard_type)
                    .or_insert_with(Vec::new)
                    .push(shard);
            }
            for (shard_type, shards) in shards {
                if shards.len() == 1 {
                    bp.build_warning(shards[0].id, format!(
                        "Only one shard defined for shard type {:?}, ignoring shard configuration",
                        shard_type.as_str()
                    ));
                    continue;
                }

                let roles = match shard_type {
                    NodeShardType::StoreMaintenance => &mut network.roles.store_maintenance,
                    NodeShardType::AccountMaintenance => &mut network.roles.account_maintenance,
                    NodeShardType::DnsAndAcme => &mut network.roles.dns_acme,
                    NodeShardType::PushNotifications => &mut network.roles.push_notifications,
                    NodeShardType::SearchIndexing => &mut network.roles.search_indexing,
                    NodeShardType::ImipProcessing => &mut network.roles.imip_processing,
                    NodeShardType::CalendarAlerts => &mut network.roles.calendar_alerts,
                    NodeShardType::MergeThreads => &mut network.roles.merge_threads,
                };

                if matches!(roles, ClusterRole::Disabled) {
                    continue;
                }

                for (shard_num, shard) in shards.iter().enumerate() {
                    if shard
                        .object
                        .node_ranges
                        .values()
                        .any(|range| range.contains(node_id))
                    {
                        if matches!(roles, ClusterRole::Enabled) {
                            *roles = ClusterRole::Sharded {
                                shard_id: shard_num as u32,
                                total_shards: shards.len() as u32,
                            };
                        } else {
                            bp.build_warning(
                                shard.id,
                                format!(
                                    "Node id {node_id} matches multiple shards for shard type {:?}",
                                    shard_type.as_str()
                                ),
                            );
                        }
                    }
                }

                if matches!(roles, ClusterRole::Enabled) {
                    bp.build_warning(
                        shards[0].id,
                        format!(
                            "Node id {node_id} does not match any shards for shard type {:?}, defaulting to all shards",
                            shard_type.as_str()
                        ),
                    );
                }
            }
        }

        network
    }
}

impl Http {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let http = bp.setting_infallible::<structs::Http>().await;

        // Parse HTTP headers
        let mut http_headers = http
            .response_headers
            .iter()
            .map(|(k, v)| {
                Ok((
                    hyper::header::HeaderName::from_str(k.trim()).map_err(|err| {
                        format!("Invalid header found in property \"http.headers\": {}", err)
                    })?,
                    hyper::header::HeaderValue::from_str(v.trim()).map_err(|err| {
                        format!("Invalid header found in property \"http.headers\": {}", err)
                    })?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| {
                bp.build_error(
                    ObjectType::Http.singleton(),
                    format!("Failed to parse HTTP headers: {}", e),
                )
            })
            .unwrap_or_default();

        // Add permissive CORS headers
        if http.use_permissive_cors {
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
                hyper::header::HeaderValue::from_static(
                    "Authorization, Content-Type, Accept, X-Requested-With",
                ),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
                hyper::header::HeaderValue::from_static(
                    "POST, GET, PATCH, PUT, DELETE, HEAD, OPTIONS",
                ),
            ));
        }

        // Add HTTP Strict Transport Security
        if http.enable_hsts {
            http_headers.push((
                hyper::header::STRICT_TRANSPORT_SECURITY,
                hyper::header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            ));
        }

        Http {
            response_url: bp.compile_expr(ObjectType::Http.singleton(), &http.ctx_base_url()),
            allowed_endpoint: bp
                .compile_expr(ObjectType::Http.singleton(), &http.ctx_allowed_endpoints()),
            rate_authenticated: http.rate_limit_authenticated,
            rate_anonymous: http.rate_limit_anonymous,
            response_headers: http_headers,
            use_forwarded: http.use_x_forwarded,
        }
    }
}

impl AsnGeoLookupConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Option<Self> {
        match bp.setting_infallible::<Asn>().await {
            Asn::Resource(asn) => Some(AsnGeoLookupConfig::Resource {
                expires: asn.expires.into_inner(),
                timeout: asn.timeout.into_inner(),
                max_size: asn.max_size as usize,
                headers: asn
                    .http_auth
                    .build_headers(asn.http_headers, None)
                    .await
                    .map_err(|err| {
                        bp.build_error(
                            ObjectType::Asn.singleton(),
                            format!("Unable to build HTTP headers: {}", err),
                        )
                    })
                    .ok()?,
                asn_resources: asn.asn_urls.into_inner(),
                geo_resources: asn.geo_urls.into_inner(),
            }),
            Asn::Dns(asn) => Some(AsnGeoLookupConfig::Dns {
                zone_ipv4: asn.zone_ip_v4,
                zone_ipv6: asn.zone_ip_v6,
                separator: asn.separator,
                index_asn: asn.index_asn as usize,
                index_asn_name: asn.index_asn_name.map(|v| v as usize),
                index_country: asn.index_country.map(|v| v as usize),
            }),
            Asn::Disabled => None,
        }
    }
}

impl ClusterRole {
    pub fn is_enabled_or_sharded(&self) -> bool {
        debug_assert!(!self.is_uninit() && !self.is_seen_role());
        matches!(self, ClusterRole::Enabled | ClusterRole::Sharded { .. })
    }

    pub fn is_enabled_for_integer(&self, value: u64) -> bool {
        debug_assert!(!self.is_uninit() && !self.is_seen_role());
        match self {
            ClusterRole::Enabled => true,
            ClusterRole::Disabled => false,
            ClusterRole::Sharded {
                shard_id,
                total_shards,
            } => (value as u32 % total_shards) == *shard_id,
        }
    }

    pub fn is_enabled_for_hash(&self, item: &impl std::hash::Hash) -> bool {
        debug_assert!(!self.is_uninit() && !self.is_seen_role());
        match self {
            ClusterRole::Enabled => true,
            ClusterRole::Disabled => false,
            ClusterRole::Sharded {
                shard_id,
                total_shards,
            } => {
                let mut hasher = Xxh3Builder::new().with_seed(201179).build();
                item.hash(&mut hasher);
                hasher.finish() % (*total_shards as u64) == *shard_id as u64
            }
        }
    }

    fn set_uninit(&mut self) {
        *self = ClusterRole::Sharded {
            shard_id: u32::MAX,
            total_shards: u32::MAX,
        };
    }

    fn set_role(&mut self, is_member: bool) -> bool {
        if self.is_uninit() {
            if is_member {
                *self = ClusterRole::Enabled;
            } else {
                *self = ClusterRole::Sharded {
                    shard_id: u32::MAX,
                    total_shards: 0,
                };
            }
            true
        } else {
            false
        }
    }

    fn is_seen_role(&self) -> bool {
        matches!(self, ClusterRole::Sharded {
                shard_id,
                total_shards,
            } if *shard_id == u32::MAX && *total_shards == 0)
    }

    fn is_uninit(&self) -> bool {
        matches!(self, ClusterRole::Sharded {
                shard_id,
                total_shards,
            } if *shard_id == u32::MAX && *total_shards == u32::MAX)
    }

    fn finalize(&mut self) {
        if self.is_uninit() {
            *self = ClusterRole::Enabled;
        } else if self.is_seen_role() {
            *self = ClusterRole::Disabled;
        }
    }
}

impl ClusterRoles {
    fn all_mut(&mut self) -> impl Iterator<Item = &mut ClusterRole> {
        [
            &mut self.store_maintenance,
            &mut self.account_maintenance,
            &mut self.push_notifications,
            &mut self.search_indexing,
            &mut self.spam_training,
            &mut self.imip_processing,
            &mut self.merge_threads,
            &mut self.calendar_alerts,
            &mut self.dns_acme,
            &mut self.outbound_mta,
            &mut self.calculate_metrics,
            &mut self.push_metrics,
            &mut self.task_manager,
            &mut self.task_scheduler,
        ]
        .into_iter()
    }
}
