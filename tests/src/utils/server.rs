/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    AssertConfig,
    store::TempDir,
    utils::{
        account::Account,
        cleanup::{search_store_destroy, store_blob_expire_all, store_destroy},
        registry::UnwrapRegistryId,
        storage::{RegistryEnvStores, assert_is_empty, build_data_store, wait_for_tasks},
    },
};
use ahash::AHashMap;
use common::{
    BuildServer, Caches, Core, Data, Inner, Server,
    auth::FALLBACK_ADMIN_ID,
    config::{
        server::{Listeners, ServerProtocol},
        storage::Storage,
        telemetry::Telemetry,
    },
    manager::{boot::build_ipc, defaults::BootstrapDefaults},
};
use http::HttpSessionManager;
use imap::core::ImapSessionManager;
use jmap_client::client::{Client, Credentials};
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use registry::{
    schema::{
        enums::{DataStoreType, EventPolicy, NetworkListenerProtocol, TracingLevel},
        prelude::{Object, SocketAddr},
        structs::{Expression, Http, NetworkListener, Tracer, TracerStdout},
    },
    types::{EnumImpl, map::Map},
};
use services::{SpawnServices, broadcast::subscriber::spawn_broadcast_subscriber};
use smtp::{
    SpawnQueueManager,
    core::SmtpSessionManager,
    queue::{
        manager::Queue,
        spool::{QueuedMessages, SmtpSpool},
    },
};
use std::{str::FromStr, sync::Arc, time::Duration};
use store::{
    RegistryStore, Store,
    registry::{bootstrap::Bootstrap, write::RegistryWrite},
};
use tokio::sync::{mpsc, watch};
use trc::EventType;
use types::id::Id;

pub struct TestServer {
    pub server: Server,
    pub accounts: AHashMap<&'static str, Account>,
    pub temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
    reset: bool,
}

pub struct TestServerBuilder {
    bootstrap: Bootstrap,
    temp_dir: TempDir,
    reset: bool,
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
            temp_dir,
            reset,
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
            enable: level.is_some(),
            level: level.unwrap_or(TracingLevel::Info),
            ansi: true,
            multiline: false,
            events: Map::new(
                EventType::variants()
                    .iter()
                    .filter(|ev| {
                        let ev = ev.as_str();
                        ev.starts_with("network.")
                            || ev == "telemetry.webhook-error"
                            || ev == "http.request-body"
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
        ipc_rxs.spawn_queue_manager(inner.clone());
        ipc_rxs.spawn_services(inner.clone());

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
        spawn_broadcast_subscriber(inner.clone(), shutdown_rx);

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        TestServer {
            server: inner.build_server(),
            temp_dir: self.temp_dir,
            accounts: AHashMap::from_iter([(
                "admin",
                Account::new("admin", "popolna_zapora", &[], Id::from(FALLBACK_ADMIN_ID)).await,
            )]),
            shutdown_tx,
            reset: self.reset,
        }
    }
}

impl TestServer {
    pub fn account(&self, name: &str) -> &Account {
        self.accounts.get(name).unwrap()
    }

    pub async fn wait_for_tasks(&self) {
        wait_for_tasks(&self.server).await;
    }

    pub async fn blob_expire_all(&self) {
        store_blob_expire_all(&self.server.core.storage.data).await;
    }

    pub async fn assert_is_empty(&self) {
        assert_is_empty(&self.server).await;
    }

    pub async fn destroy_store(&self) {
        store_destroy(self.server.store()).await;
    }

    pub fn is_reset(&self) -> bool {
        self.reset
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
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
        destroy_all_mailboxes_no_wait(account.client()).await;
    }
}

pub async fn destroy_all_mailboxes_for_account(account_id: u32) {
    let mut client = Client::new()
        .credentials(Credentials::basic("admin", "secret"))
        .follow_redirects(["127.0.0.1"])
        .timeout(Duration::from_secs(3600))
        .accept_invalid_certs(true)
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    client.set_default_account_id(Id::from(account_id));
    destroy_all_mailboxes_no_wait(&client).await;
}

async fn destroy_all_mailboxes_no_wait(client: &Client) {
    let mut request = client.build();
    request.query_mailbox().arguments().sort_as_tree(true);
    let mut ids = request.send_query_mailbox().await.unwrap().take_ids();
    ids.reverse();
    for id in ids {
        client.mailbox_destroy(&id, true).await.unwrap();
    }
}
