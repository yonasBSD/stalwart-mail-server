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
use registry::schema::{
    enums::ClusterTaskType,
    prelude::ObjectType,
    structs::{self, Asn, ClusterTaskGroup, HttpForm, Rate, SystemSettings, TaskManager},
};
use std::{str::FromStr, time::Duration};

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

#[derive(Clone)]
pub struct ClusterRoles {
    pub store_maintenance: bool,
    pub account_maintenance: bool,
    pub push_notifications: bool,
    pub search_indexing: bool,
    pub spam_training: bool,
    pub metrics_calculate: bool,
    pub metrics_push: bool,
    pub outbound_mta: bool,
    pub task_scheduler: bool,
    pub task_manager: bool,
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
            node_id: bp.node_id() as u64,
            server_name: system.default_hostname,
            security: Security::parse(bp).await,
            contact_form: ContactForm::parse(bp).await,
            asn_geo_lookup: AsnGeoLookupConfig::parse(bp).await.unwrap_or_default(),
            roles: ClusterRoles::default(),
            http: Http::parse(bp).await,
            task_manager: bp.setting_infallible::<TaskManager>().await,
        };

        if let Some(role) = &bp.role {
            match &role.tasks {
                ClusterTaskGroup::EnableAll => {}
                ClusterTaskGroup::DisableAll => {
                    for network_role in network.roles.all_mut() {
                        *network_role = false;
                    }
                }
                ClusterTaskGroup::EnableSome(group) => {
                    for network_role in network.roles.all_mut() {
                        *network_role = false;
                    }
                    for task_type in group.task_types.iter() {
                        network.roles.set_role(*task_type, true);
                    }
                }
                ClusterTaskGroup::DisableSome(group) => {
                    for task_type in group.task_types.iter() {
                        network.roles.set_role(*task_type, false);
                    }
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

impl ClusterRoles {
    fn all_mut(&mut self) -> impl Iterator<Item = &mut bool> {
        [
            &mut self.store_maintenance,
            &mut self.account_maintenance,
            &mut self.push_notifications,
            &mut self.search_indexing,
            &mut self.spam_training,
            &mut self.outbound_mta,
            &mut self.task_manager,
            &mut self.task_scheduler,
            &mut self.metrics_calculate,
            &mut self.metrics_push,
        ]
        .into_iter()
    }

    fn set_role(&mut self, role: ClusterTaskType, enabled: bool) {
        match role {
            ClusterTaskType::StoreMaintenance => self.store_maintenance = enabled,
            ClusterTaskType::AccountMaintenance => self.account_maintenance = enabled,
            ClusterTaskType::PushNotifications => self.push_notifications = enabled,
            ClusterTaskType::SearchIndexing => self.search_indexing = enabled,
            ClusterTaskType::SpamClassifierTraining => self.spam_training = enabled,
            ClusterTaskType::MetricsCalculate => self.metrics_calculate = enabled,
            ClusterTaskType::MetricsPush => self.metrics_push = enabled,
            ClusterTaskType::OutboundMta => self.outbound_mta = enabled,
            ClusterTaskType::TaskQueueProcessing => self.task_manager = enabled,
            ClusterTaskType::TaskScheduler => self.task_scheduler = enabled,
        }
    }
}

impl Default for ClusterRoles {
    fn default() -> Self {
        ClusterRoles {
            store_maintenance: true,
            account_maintenance: true,
            push_notifications: true,
            search_indexing: true,
            spam_training: true,
            metrics_calculate: true,
            metrics_push: true,
            outbound_mta: true,
            task_manager: true,
            task_scheduler: true,
        }
    }
}
