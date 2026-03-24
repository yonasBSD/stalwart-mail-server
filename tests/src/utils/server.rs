/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    AssertConfig,
    smtp::session::{DummyIo, TestSession},
    utils::{
        account::Account,
        cleanup::{search_store_destroy, store_blob_expire_all, store_destroy},
        registry::UnwrapRegistryId,
        storage::{RegistryEnvStores, assert_is_empty, build_data_store, wait_for_tasks},
        temp_dir::TempDir,
    },
};
use ahash::AHashMap;
use common::{
    BuildServer, Caches, Core, Data, DavResources, Inner, Server,
    auth::FALLBACK_ADMIN_ID,
    config::{
        server::{Listeners, ServerProtocol},
        storage::Storage,
        telemetry::Telemetry,
    },
    ipc::{QueueEvent, ReportingEvent},
    manager::{
        boot::{IpcReceivers, build_ipc},
        defaults::BootstrapDefaults,
    },
};
use email::message::metadata::MessageMetadata;
use groupware::cache::GroupwareCache;
use http::HttpSessionManager;
use imap::core::ImapSessionManager;
use jmap_client::client::Client;
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use registry::{
    schema::{
        enums::{DataStoreType, EventPolicy, NetworkListenerProtocol, TracingLevel},
        prelude::{Object, SocketAddr},
        structs::{
            Certificate, Expression, Http, NetworkListener, PublicText, SecretKeyFile, SecretText,
            Tracer, TracerStdout,
        },
    },
    types::{EnumImpl, map::Map},
};
use services::{SpawnServices, broadcast::subscriber::spawn_broadcast_subscriber};
use smtp::{
    SpawnQueueManager,
    core::{Session, SmtpSessionManager},
    queue::{
        manager::{Queue, SpawnQueue},
        spool::{QueuedMessages, SmtpSpool},
    },
    reporting::scheduler::SpawnReport,
};
use std::{path::PathBuf, str::FromStr, sync::Arc};
use store::{
    RegistryStore, Store, ValueKey,
    registry::{bootstrap::Bootstrap, write::RegistryWrite},
    write::{AlignedBytes, Archive},
};
use tokio::sync::{mpsc, watch};
use trc::EventType;
use types::{collection::Collection, field::EmailField, id::Id};

pub struct TestServer {
    pub server: Server,
    pub accounts: AHashMap<&'static str, Account>,
    pub temp_dir: TempDir,
    pub queue_rx: mpsc::Receiver<QueueEvent>,
    pub report_rx: mpsc::Receiver<ReportingEvent>,
    shutdown_tx: watch::Sender<bool>,
    reset: bool,
}

pub struct TestServerBuilder {
    bootstrap: Bootstrap,
    temp_dir: TempDir,
    http_listener_port: u16,
    reset: bool,
    logging_enabled: bool,
    capture_queue: bool,
    capture_reporting: bool,
    disable_services: bool,
}

impl TestServerBuilder {
    pub async fn new(test_name: &str) -> Self {
        let reset = std::env::var("NO_INSERT").is_err();
        let temp_dir = TempDir::new(test_name, reset);
        let path = temp_dir.path.to_string_lossy().to_string();
        let data_store = build_data_store(
            std::env::var("STORE")
                .map(|store| DataStoreType::parse(&store).expect("Invalid store type"))
                .expect(concat!(
                    "Missing or invalid store type. Try ",
                    "running `STORE=<store_type> cargo test`"
                )),
            &path,
        );
        let store = Store::build(data_store).await.unwrap();

        store.create_tables().await.unwrap();

        // Delete old store if requested
        if reset {
            store_destroy(&store).await;
        }

        Self {
            bootstrap: Bootstrap::new(
                RegistryStore::new(&path, store, "mail.example.org".to_string(), 1, None).await,
            )
            .await,
            http_listener_port: 8899,
            temp_dir,
            reset,
            logging_enabled: false,
            capture_queue: false,
            capture_reporting: false,
            disable_services: false,
        }
    }

    pub async fn with_default_listeners(self) -> Self {
        let mut this = self;
        for (protocol, name, port, use_tls) in [
            (NetworkListenerProtocol::Http, "jmap", 8899, true),
            (NetworkListenerProtocol::Imap, "imap", 9991, false),
            (NetworkListenerProtocol::Imap, "imaptls", 9992, true),
            (NetworkListenerProtocol::ManageSieve, "sieve", 4190, true),
            (NetworkListenerProtocol::Pop3, "pop3", 4110, true),
            (NetworkListenerProtocol::Lmtp, "lmtp-debug", 11200, false),
        ] {
            this = this.with_listener(protocol, name, port, use_tls).await;
        }
        this.with_object(Http {
            base_url: Expression {
                else_: "'https://127.0.0.1:8899'".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
    }

    pub async fn with_http_listener(mut self, port: u16) -> Self {
        self.http_listener_port = port;
        self.with_listener(NetworkListenerProtocol::Http, "jmap", port, true)
            .await
            .with_object(Http {
                base_url: Expression {
                    else_: format!("'https://127.0.0.1:{}'", port),

                    ..Default::default()
                },
                ..Default::default()
            })
            .await
    }

    pub async fn with_smtp_listener(self, port: u16) -> Self {
        self.with_listener(NetworkListenerProtocol::Smtp, "smtp", port, false)
            .await
    }

    pub async fn with_dummy_tls_cert(self) -> Self {
        let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cert_path.push("resources");
        let mut cert = cert_path.clone();
        cert.push("tls_cert.pem");
        let mut pk = cert_path.clone();
        pk.push("tls_privatekey.pem");

        self.with_object(Certificate {
            private_key: SecretText::File(SecretKeyFile {
                file_path: pk.to_string_lossy().to_string(),
            }),
            certificate: PublicText::File(SecretKeyFile {
                file_path: cert.to_string_lossy().to_string(),
            }),

            ..Default::default()
        })
        .await
    }

    pub async fn with_listener(
        self,
        protocol: NetworkListenerProtocol,
        name: &str,
        port: u16,
        tls_implicit: bool,
    ) -> Self {
        self.insert_object(NetworkListener {
            bind: Map::new(vec![
                SocketAddr::from_str(&format!("127.0.0.1:{port}")).unwrap(),
            ]),
            name: name.to_string(),
            protocol,
            use_tls: true,
            tls_implicit,
            ..Default::default()
        })
        .await;
        self
    }

    pub async fn with_object(self, object: impl Into<Object>) -> Self {
        self.insert_object(object).await;
        self
    }

    pub fn with_logging(mut self) -> Self {
        self.logging_enabled = true;
        self
    }

    pub fn capture_queue(mut self) -> Self {
        self.capture_queue = true;
        self
    }

    pub fn capture_reporting(mut self) -> Self {
        self.capture_reporting = true;
        self
    }

    pub fn disable_services(mut self) -> Self {
        self.disable_services = true;
        self
    }

    pub async fn insert_object(&self, object: impl Into<Object>) -> Id {
        self.bootstrap
            .registry
            .write(RegistryWrite::insert(&object.into()))
            .await
            .unwrap()
            .unwrap_id(trc::location!())
    }

    pub async fn build(mut self) -> TestServer {
        // Register stores from environment
        self.bootstrap.registry.insert_stores_from_env().await;

        // Enable logging if requested
        let level = std::env::var("LOG")
            .map(|log| TracingLevel::parse(&log).expect("Invalid log level"))
            .ok();

        self.insert_object(Tracer::Stdout(TracerStdout {
            enable: level.is_some() || self.logging_enabled,
            level: level.unwrap_or(TracingLevel::Info),
            ansi: true,
            multiline: false,
            events: Map::new(
                EventType::variants()
                    .iter()
                    .filter(|ev| {
                        let ev = ev.as_str();
                        ev.starts_with("network.")
                            || ev.starts_with("http.connection-")
                            || ev == "telemetry.webhook-error"
                            || ev == "http.request-body"
                            || ev == "http.request-url"
                            || ev == "tls.no-certificates-available"
                            || ev == "store.cache-hit"
                    })
                    .copied()
                    .collect(),
            ),
            events_policy: EventPolicy::Exclude,
            ..Default::default()
        }))
        .await;

        // Start listeners
        let mut servers = Listeners::parse(&mut self.bootstrap).await;
        servers.bind_and_drop_priv(&mut self.bootstrap);

        // Parse storage
        let storage = Storage::parse(&mut self.bootstrap).await;

        // Reset search store
        if self.reset {
            search_store_destroy(&storage.search).await;
        }

        // Parse telemetry
        let telemetry = Telemetry::parse(&mut self.bootstrap, &storage).await;

        // Add safe defaults if missing
        self.bootstrap.insert_safe_defaults().await;

        // Parse components
        let core = Box::pin(Core::parse(&mut self.bootstrap, storage)).await;
        let data = Data::parse(&mut self.bootstrap).await;
        let cache = Caches::parse(&mut self.bootstrap).await;

        // Enable telemetry
        telemetry.enable(true);

        // Build inner
        let (ipc, mut ipc_rxs) = build_ipc(!core.storage.coordinator.is_none());
        let inner = Arc::new(Inner {
            shared_core: core.into_shared(),
            data,
            ipc,
            cache,
        });

        // Parse TCP acceptors
        servers
            .parse_tcp_acceptors(&mut self.bootstrap, inner.clone())
            .await;

        // Start services
        self.bootstrap.assert_no_errors();
        if !self.disable_services {
            ipc_rxs.spawn_services(inner.clone());
        }

        // Spawn queue manager if not capturing
        let (_, mut queue_rx) = mpsc::channel(100);
        let (_, mut report_rx) = mpsc::channel(100);
        if !self.capture_queue && !self.capture_reporting {
            ipc_rxs.spawn_queue_manager(inner.clone());
        } else {
            let queue_rx_ = ipc_rxs.queue_rx.take().unwrap();
            let report_rx_ = ipc_rxs.report_rx.take().unwrap();
            if !self.capture_queue {
                queue_rx_.spawn(inner.clone());
            } else {
                queue_rx = queue_rx_;
            }
            if !self.capture_reporting {
                report_rx_.spawn(inner.clone());
            } else {
                report_rx = report_rx_;
            }
        }

        // Spawn servers
        let (shutdown_tx, shutdown_rx) = servers.spawn(|server, acceptor, shutdown_rx| {
            match &server.protocol {
                ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                    SmtpSessionManager::new(inner.clone()),
                    inner.clone(),
                    acceptor,
                    shutdown_rx,
                ),
                ServerProtocol::Http => server.spawn(
                    HttpSessionManager::new(inner.clone()),
                    inner.clone(),
                    acceptor,
                    shutdown_rx,
                ),
                ServerProtocol::Imap => server.spawn(
                    ImapSessionManager::new(inner.clone()),
                    inner.clone(),
                    acceptor,
                    shutdown_rx,
                ),
                ServerProtocol::Pop3 => server.spawn(
                    Pop3SessionManager::new(inner.clone()),
                    inner.clone(),
                    acceptor,
                    shutdown_rx,
                ),
                ServerProtocol::ManageSieve => server.spawn(
                    ManageSieveSessionManager::new(inner.clone()),
                    inner.clone(),
                    acceptor,
                    shutdown_rx,
                ),
            };
        });

        // Start broadcast subscriber
        if !self.disable_services {
            spawn_broadcast_subscriber(inner.clone(), shutdown_rx);
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut admin = Account::new(
            "admin",
            "popolna_zapora",
            &[],
            "Recovery Admin",
            Id::from(FALLBACK_ADMIN_ID),
        );
        admin.http_listener_port = self.http_listener_port;

        TestServer {
            server: inner.build_server(),
            temp_dir: self.temp_dir,
            accounts: AHashMap::from_iter([("admin", admin)]),
            queue_rx,
            report_rx,
            shutdown_tx,
            reset: self.reset,
        }
    }
}

impl TestServer {
    pub fn reload_core(&mut self) {
        self.server = self.server.inner.build_server();
    }

    pub fn account(&self, name: &str) -> &Account {
        self.accounts.get(name).unwrap()
    }

    pub async fn wait_for_tasks(&self) {
        wait_for_tasks(&self.server, false).await;
    }

    pub async fn wait_for_tasks_skip_failures(&self) {
        wait_for_tasks(&self.server, true).await;
    }

    pub async fn blob_expire_all(&self) {
        store_blob_expire_all(&self.server.core.storage.data).await;
    }

    pub async fn assert_is_empty(&self) {
        assert_is_empty(&self.server, true).await;
    }

    pub async fn cleanup(&self) {
        self.assert_is_empty().await;
        self.server.invalidate_all_local_caches();
    }

    pub async fn destroy_store(&self) {
        store_destroy(self.server.store()).await;
    }

    pub fn is_reset(&self) -> bool {
        self.reset
    }

    pub fn tmp_dir(&self) -> &str {
        self.temp_dir.path.as_os_str().to_str().unwrap()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn new_mta_session(&self) -> Session<DummyIo> {
        Session::test(self.server.clone())
    }

    pub fn new_mta_session_with_shutdown(&self) -> (Session<DummyIo>, watch::Sender<bool>) {
        let (tx, rx) = watch::channel(true);
        (Session::test_with_shutdown(self.server.clone(), rx), tx)
    }

    pub async fn resources(&self, name: &'static str, collection: Collection) -> Arc<DavResources> {
        let account_id = self.account(name).id().document_id();
        self.server
            .fetch_dav_resources(account_id, account_id, collection.into())
            .await
            .unwrap()
    }

    pub async fn fetch_email(&self, account_id: u32, document_id: u32) -> Vec<u8> {
        let metadata_ = self
            .server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                Collection::Email,
                document_id,
                EmailField::Metadata,
            ))
            .await
            .unwrap()
            .unwrap();
        self.server
            .blob_store()
            .get_blob(
                metadata_
                    .unarchive::<MessageMetadata>()
                    .unwrap()
                    .blob_hash
                    .0
                    .as_slice(),
                0..usize::MAX,
            )
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn all_queued_messages(&self) -> QueuedMessages {
        self.server
            .next_event(&mut Queue::new(
                self.server.inner.clone(),
                mpsc::channel(100).1,
            ))
            .await
    }

    pub async fn destroy_all_mailboxes(&self, account: &Account) {
        self.wait_for_tasks().await;
        account.jmap_client().await.destroy_all_mailboxes().await;
    }

    pub async fn inner_with_rxs(&self) -> (Arc<Inner>, IpcReceivers) {
        let (ipc, ipc_rxs) = build_ipc(false);

        let mut bp = Bootstrap::new_uninitialized(self.server.registry().clone());

        (
            Inner {
                shared_core: self.server.core.as_ref().clone().into_shared(),
                data: Default::default(),
                ipc,
                cache: Caches::parse(&mut bp).await,
            }
            .into(),
            ipc_rxs,
        )
    }
}

impl Account {
    pub async fn destroy_all_mailboxes_for_account(&self, account_id: u32) {
        let mut client = self.jmap_client().await;
        client.set_default_account_id(Id::from(account_id));
        client.destroy_all_mailboxes().await;
    }
}

pub trait DestroyAllMailboxes {
    fn destroy_all_mailboxes(&self) -> impl Future<Output = ()>;
}

impl DestroyAllMailboxes for Client {
    async fn destroy_all_mailboxes(&self) {
        let mut request = self.build();
        request.query_mailbox().arguments().sort_as_tree(true);
        let mut ids = request.send_query_mailbox().await.unwrap().take_ids();
        ids.reverse();
        for id in ids {
            self.mailbox_destroy(&id, true).await.unwrap();
        }
    }
}
