/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, net::IpAddr, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use config::{
    imap::ImapConfig,
    jmap::settings::JmapConfig,
    scripts::Scripting,
    server::ServerProtocol,
    smtp::{
        auth::{ArcSealer, DkimSigner},
        queue::RelayHost,
        SmtpConfig,
    },
    storage::Storage,
    tracers::{OtelTracer, Tracer, Tracers},
};
use directory::{
    core::secret::verify_secret_hash, Directory, DirectoryError, Principal, QueryBy, Type,
};
use expr::if_block::IfBlock;
use listener::{
    blocked::{AllowedIps, BlockedIps},
    tls::TlsManager,
};
use mail_send::Credentials;
use opentelemetry::KeyValue;
use opentelemetry_sdk::{
    trace::{self, Sampler},
    Resource,
};
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_VERSION};
use se_licensing::license::LicenseKey;
use sieve::Sieve;
use store::LookupStore;
use tokio::sync::{mpsc, oneshot};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};
use utils::{config::Config, BlobHash};
use webhooks::{manager::WebhookEvent, WebhookPayload, WebhookType, Webhooks};

pub mod addresses;
pub mod config;
pub mod expr;
pub mod listener;
pub mod manager;
pub mod scripts;
pub mod webhooks;

pub static USER_AGENT: &str = concat!("Stalwart/", env!("CARGO_PKG_VERSION"),);
pub static DAEMON_NAME: &str = concat!("Stalwart Mail Server v", env!("CARGO_PKG_VERSION"),);

pub const IPC_CHANNEL_BUFFER: usize = 1024;

pub type SharedCore = Arc<ArcSwap<Core>>;

#[derive(Clone, Default)]
pub struct Core {
    pub storage: Storage,
    pub sieve: Scripting,
    pub network: Network,
    pub tls: TlsManager,
    pub smtp: SmtpConfig,
    pub jmap: JmapConfig,
    pub imap: ImapConfig,
    pub web_hooks: Webhooks,
    pub enterprise: Option<Enterprise>,
}

#[derive(Clone)]
pub struct Network {
    pub blocked_ips: BlockedIps,
    pub allowed_ips: AllowedIps,
    pub url: IfBlock,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL

#[derive(Clone)]
pub struct Enterprise {
    pub license: LicenseKey,
    pub undelete_period: Option<Duration>,
}

// SPDX-SnippetEnd

pub enum AuthResult<T> {
    Success(T),
    Failure(AuthFailureReason),
}

pub enum AuthFailureReason {
    InvalidCredentials,
    MissingTotp,
    Banned,
    InternalError(DirectoryError),
}

#[derive(Debug)]
pub enum DeliveryEvent {
    Ingest {
        message: IngestMessage,
        result_tx: oneshot::Sender<Vec<DeliveryResult>>,
    },
    Stop,
}

pub struct Ipc {
    pub delivery_tx: mpsc::Sender<DeliveryEvent>,
    pub webhook_tx: mpsc::Sender<WebhookEvent>,
}

#[derive(Debug)]
pub struct IngestMessage {
    pub sender_address: String,
    pub recipients: Vec<String>,
    pub message_blob: BlobHash,
    pub message_size: usize,
}

#[derive(Debug, Clone)]
pub enum DeliveryResult {
    Success,
    TemporaryFailure {
        reason: Cow<'static, str>,
    },
    PermanentFailure {
        code: [u8; 3],
        reason: Cow<'static, str>,
    },
}

pub trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

impl Core {
    pub fn get_directory(&self, name: &str) -> Option<&Arc<Directory>> {
        self.storage.directories.get(name)
    }

    pub fn get_directory_or_default(&self, name: &str) -> &Arc<Directory> {
        self.storage.directories.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_directory",
                event = "error",
                directory = name,
                "Directory not found, using default."
            );

            &self.storage.directory
        })
    }

    pub fn get_lookup_store(&self, name: &str) -> &LookupStore {
        self.storage.lookups.get(name).unwrap_or_else(|| {
            tracing::debug!(
                context = "get_lookup_store",
                event = "error",
                directory = name,
                "Store not found, using default."
            );

            &self.storage.lookup
        })
    }

    pub fn get_arc_sealer(&self, name: &str) -> Option<&ArcSealer> {
        self.smtp
            .mail_auth
            .sealers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                tracing::warn!(
                    context = "get_arc_sealer",
                    event = "error",
                    name = name,
                    "Arc sealer not found."
                );

                None
            })
    }

    pub fn get_dkim_signer(&self, name: &str) -> Option<&DkimSigner> {
        self.smtp
            .mail_auth
            .signers
            .get(name)
            .map(|s| s.as_ref())
            .or_else(|| {
                tracing::warn!(
                    context = "get_dkim_signer",
                    event = "error",
                    name = name,
                    "DKIM signer not found."
                );

                None
            })
    }

    pub fn get_sieve_script(&self, name: &str) -> Option<&Arc<Sieve>> {
        self.sieve.scripts.get(name).or_else(|| {
            tracing::warn!(
                context = "get_sieve_script",
                event = "error",
                name = name,
                "Sieve script not found."
            );

            None
        })
    }

    pub fn get_relay_host(&self, name: &str) -> Option<&RelayHost> {
        self.smtp.queue.relay_hosts.get(name).or_else(|| {
            tracing::warn!(
                context = "get_relay_host",
                event = "error",
                name = name,
                "Remote host not found."
            );

            None
        })
    }

    pub async fn authenticate(
        &self,
        directory: &Directory,
        ipc: &Ipc,
        credentials: &Credentials<String>,
        remote_ip: IpAddr,
        protocol: ServerProtocol,
        return_member_of: bool,
    ) -> directory::Result<AuthResult<Principal<u32>>> {
        // First try to authenticate the user against the default directory
        let result = match directory
            .query(QueryBy::Credentials(credentials), return_member_of)
            .await
        {
            Ok(Some(principal)) => {
                // Send webhook event
                if self.has_webhook_subscribers(WebhookType::AuthSuccess) {
                    ipc.send_webhook(
                        WebhookType::AuthSuccess,
                        WebhookPayload::Authentication {
                            login: credentials.login().to_string(),
                            protocol,
                            remote_ip,
                            typ: principal.typ.into(),
                            as_master: None,
                        },
                    )
                    .await;
                }

                return Ok(AuthResult::Success(principal));
            }
            Ok(None) => Ok(()),
            Err(DirectoryError::MissingTotpCode) => {
                return Ok(AuthResult::Failure(AuthFailureReason::MissingTotp))
            }
            Err(err) => Err(err),
        };

        // Then check if the credentials match the fallback admin or master user
        match (
            &self.jmap.fallback_admin,
            &self.jmap.master_user,
            credentials,
        ) {
            (Some((fallback_admin, fallback_pass)), _, Credentials::Plain { username, secret })
                if username == fallback_admin =>
            {
                if verify_secret_hash(fallback_pass, secret).await {
                    // Send webhook event
                    if self.has_webhook_subscribers(WebhookType::AuthSuccess) {
                        ipc.send_webhook(
                            WebhookType::AuthSuccess,
                            WebhookPayload::Authentication {
                                login: username.to_string(),
                                protocol,
                                remote_ip,
                                typ: Type::Superuser.into(),
                                as_master: None,
                            },
                        )
                        .await;
                    }
                    return Ok(AuthResult::Success(Principal::fallback_admin(
                        fallback_pass,
                    )));
                }
            }
            (_, Some((master_user, master_pass)), Credentials::Plain { username, secret })
                if username.ends_with(master_user) =>
            {
                if verify_secret_hash(master_pass, secret).await {
                    let username = username.strip_suffix(master_user).unwrap();
                    let username = username.strip_suffix('%').unwrap_or(username);
                    return Ok(
                        if let Some(principal) = directory
                            .query(QueryBy::Name(username), return_member_of)
                            .await?
                        {
                            // Send webhook event
                            if self.has_webhook_subscribers(WebhookType::AuthSuccess) {
                                ipc.send_webhook(
                                    WebhookType::AuthSuccess,
                                    WebhookPayload::Authentication {
                                        login: username.to_string(),
                                        protocol,
                                        remote_ip,
                                        typ: principal.typ.into(),
                                        as_master: true.into(),
                                    },
                                )
                                .await;
                            }
                            AuthResult::Success(principal)
                        } else {
                            // Send webhook event
                            if self.has_webhook_subscribers(WebhookType::AuthFailure) {
                                ipc.send_webhook(
                                    WebhookType::AuthFailure,
                                    WebhookPayload::Authentication {
                                        login: username.to_string(),
                                        protocol,
                                        remote_ip,
                                        typ: None,
                                        as_master: true.into(),
                                    },
                                )
                                .await;
                            }

                            AuthResult::Failure(AuthFailureReason::InvalidCredentials)
                        },
                    );
                }
            }
            _ => {}
        }

        if let Err(err) = result {
            // Send webhook event
            if self.has_webhook_subscribers(WebhookType::AuthError) {
                ipc.send_webhook(
                    WebhookType::AuthError,
                    WebhookPayload::Error {
                        message: err.to_string(),
                    },
                )
                .await;
            }

            Err(err)
        } else if self.has_fail2ban() {
            let login = credentials.login();
            if self.is_fail2banned(remote_ip, login.to_string()).await? {
                tracing::info!(
                    context = "directory",
                    event = "fail2ban",
                    remote_ip = ?remote_ip,
                    login = ?login,
                    "IP address blocked after too many failed login attempts",
                );

                // Send webhook event
                if self.has_webhook_subscribers(WebhookType::AuthBanned) {
                    ipc.send_webhook(
                        WebhookType::AuthBanned,
                        WebhookPayload::Authentication {
                            login: credentials.login().to_string(),
                            protocol,
                            remote_ip,
                            typ: None,
                            as_master: None,
                        },
                    )
                    .await;
                }

                Ok(AuthResult::Failure(AuthFailureReason::Banned))
            } else {
                // Send webhook event
                if self.has_webhook_subscribers(WebhookType::AuthFailure) {
                    ipc.send_webhook(
                        WebhookType::AuthFailure,
                        WebhookPayload::Authentication {
                            login: credentials.login().to_string(),
                            protocol,
                            remote_ip,
                            typ: None,
                            as_master: None,
                        },
                    )
                    .await;
                }

                Ok(AuthResult::Failure(AuthFailureReason::InvalidCredentials))
            }
        } else {
            // Send webhook event
            if self.has_webhook_subscribers(WebhookType::AuthFailure) {
                ipc.send_webhook(
                    WebhookType::AuthFailure,
                    WebhookPayload::Authentication {
                        login: credentials.login().to_string(),
                        protocol,
                        remote_ip,
                        typ: None,
                        as_master: None,
                    },
                )
                .await;
            }
            Ok(AuthResult::Failure(AuthFailureReason::InvalidCredentials))
        }
    }
}

impl Tracers {
    pub fn enable(self, config: &mut Config) -> Option<Vec<WorkerGuard>> {
        let mut layers: Option<Box<dyn Layer<Registry> + Sync + Send>> = None;
        let mut guards = Vec::new();

        for tracer in self.tracers {
            let (Tracer::Stdout { level, .. }
            | Tracer::Log { level, .. }
            | Tracer::Journal { level }
            | Tracer::Otel { level, .. }) = tracer;

            let filter = match EnvFilter::builder().parse(format!(
                "smtp={level},imap={level},jmap={level},pop3={level},store={level},common={level},utils={level},directory={level},se_common={level}"
            )) {
                Ok(filter) => {
                    filter
                }
                Err(err) => {
                    config.new_build_error("tracer", format!("Failed to set env filter: {err}"));
                    continue;
                }
            };

            let layer = match tracer {
                Tracer::Stdout { ansi, .. } => tracing_subscriber::fmt::layer()
                    .with_ansi(ansi)
                    .with_filter(filter)
                    .boxed(),
                Tracer::Log { appender, ansi, .. } => {
                    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
                    guards.push(guard);
                    tracing_subscriber::fmt::layer()
                        .with_writer(non_blocking)
                        .with_ansi(ansi)
                        .with_filter(filter)
                        .boxed()
                }
                Tracer::Otel { tracer, .. } => {
                    let tracer = match tracer {
                        OtelTracer::Gprc(exporter) => opentelemetry_otlp::new_pipeline()
                            .tracing()
                            .with_exporter(exporter),
                        OtelTracer::Http(exporter) => opentelemetry_otlp::new_pipeline()
                            .tracing()
                            .with_exporter(exporter),
                    }
                    .with_trace_config(
                        trace::config()
                            .with_resource(Resource::new(vec![
                                KeyValue::new(SERVICE_NAME, "stalwart-mail".to_string()),
                                KeyValue::new(
                                    SERVICE_VERSION,
                                    env!("CARGO_PKG_VERSION").to_string(),
                                ),
                            ]))
                            .with_sampler(Sampler::AlwaysOn),
                    )
                    .install_batch(opentelemetry_sdk::runtime::Tokio);

                    match tracer {
                        Ok(tracer) => tracing_opentelemetry::layer()
                            .with_tracer(tracer)
                            .with_filter(filter)
                            .boxed(),
                        Err(err) => {
                            config.new_build_error(
                                "tracer",
                                format!("Failed to start OpenTelemetry: {err}"),
                            );
                            continue;
                        }
                    }
                }
                Tracer::Journal { .. } => {
                    #[cfg(unix)]
                    {
                        match tracing_journald::layer() {
                            Ok(layer) => layer.with_filter(filter).boxed(),
                            Err(err) => {
                                config.new_build_error(
                                    "tracer",
                                    format!("Failed to start Journald: {err}"),
                                );
                                continue;
                            }
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        config.new_build_error(
                            "tracer",
                            "Journald is only available on Unix systems.",
                        );
                        continue;
                    }
                }
            };

            layers = Some(match layers {
                Some(layers) => layers.and_then(layer).boxed(),
                None => layer,
            });
        }

        match tracing_subscriber::registry().with(layers?).try_init() {
            Ok(_) => Some(guards),
            Err(err) => {
                config.new_build_error("tracer", format!("Failed to start tracing: {err}"));
                None
            }
        }
    }
}

trait CredentialsUsername {
    fn login(&self) -> &str;
}

impl CredentialsUsername for Credentials<String> {
    fn login(&self) -> &str {
        match self {
            Credentials::Plain { username, .. }
            | Credentials::XOauth2 { username, .. }
            | Credentials::OAuthBearer { token: username } => username,
        }
    }
}
