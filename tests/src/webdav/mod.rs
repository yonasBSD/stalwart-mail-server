/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    AssertConfig, TEST_USERS, add_test_certs,
    directory::internal::TestInternalDirectory,
    jmap::{assert_is_empty, wait_for_tasks},
    store::{
        TempDir, build_store_config,
        cleanup::{search_store_destroy, store_destroy},
    },
};
use ::managesieve::core::ManageSieveSessionManager;
use ahash::{AHashMap, AHashSet};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{
    Caches, Core, Data, DavResource, DavResources, Inner, Server,
    config::{
        server::{Listeners, ServerProtocol},
        telemetry::Telemetry,
    },
    manager::boot::build_ipc,
};
use dav_proto::{
    schema::property::{DavProperty, WebDavProperty},
    xml_pretty_print,
};
use email::message::metadata::MessageMetadata;
use groupware::{DavResourceName, cache::GroupwareCache};
use http::HttpSessionManager;
use hyper::{HeaderMap, Method, StatusCode, header::AUTHORIZATION};
use imap::core::ImapSessionManager;
use pop3::Pop3SessionManager;
use quick_xml::Reader;
use quick_xml::events::Event;
use services::SpawnServices;
use smtp::{SpawnQueueManager, core::SmtpSessionManager};
use std::{borrow::Cow, str};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    ValueKey,
    rand::{Rng, distr::Alphanumeric, rng},
    write::{AlignedBytes, Archive},
};
use tokio::sync::watch;
use types::{collection::Collection, field::EmailField};
use utils::config::Config;

pub mod acl;
pub mod basic;
pub mod cal_alarm;
pub mod cal_itip;
pub mod cal_query;
pub mod cal_scheduling;
pub mod card_query;
pub mod copy_move;
pub mod lock;
pub mod mkcol;
pub mod multiget;
pub mod principals;
pub mod prop;
pub mod put_get;
pub mod sync;

#[test]
fn webdav_tests() {
    //test_build_itip_templates(&handle.server).await;

    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(8 * 1024 * 1024) // 8MB stack
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // Prepare settings
            let assisted_discovery = std::env::var("ASSISTED_DISCOVERY").unwrap_or_default() == "1";
            let start_time = Instant::now();
            let delete = true;
            let handle = init_webdav_tests(assisted_discovery, delete).await;

            basic::test(&handle).await;
            put_get::test(&handle).await;
            mkcol::test(&handle).await;
            copy_move::test(&handle, assisted_discovery).await;
            prop::test(&handle, assisted_discovery).await;
            multiget::test(&handle).await;
            sync::test(&handle).await;
            lock::test(&handle).await;
            principals::test(&handle, assisted_discovery).await;
            acl::test(&handle).await;
            card_query::test(&handle).await;
            cal_query::test(&handle).await;
            cal_alarm::test(&handle).await;
            cal_itip::test();
            cal_scheduling::test(&handle).await;

            // Print elapsed time
            let elapsed = start_time.elapsed();
            println!(
                "Elapsed: {}.{:03}s",
                elapsed.as_secs(),
                elapsed.subsec_millis()
            );

            // Remove test data
            if delete {
                handle.temp_dir.delete();
            }
        });
}

#[allow(dead_code)]
pub struct WebDavTest {
    server: Server,
    clients: AHashMap<&'static str, DummyWebDavClient>,
    temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
}

async fn init_webdav_tests(assisted_discovery: bool, delete_if_exists: bool) -> WebDavTest {
    // Load and parse config
    let temp_dir = TempDir::new("webdav_tests", delete_if_exists);
    let mut config = Config::new(
        add_test_certs(&(build_store_config(&temp_dir.path.to_string_lossy()) + SERVER))
            .replace("{TMP}", &temp_dir.path.display().to_string())
            .replace("{ASSISTED_DISCOVERY}", &assisted_discovery.to_string())
            .replace(
                "{LEVEL}",
                &std::env::var("LOG").unwrap_or_else(|_| "disable".to_string()),
            ),
    )
    .unwrap();
    config.resolve_all_macros().await;

    // Parse servers
    let mut servers = Listeners::parse(&mut config);

    // Bind ports and drop privileges
    servers.bind_and_drop_priv(&mut config);

    // Build stores
    let stores = Stores::parse_all(&mut config, false).await;

    // Parse core
    let tracers = Telemetry::parse(&mut config, &stores);
    let core = Core::parse(&mut config, stores, Default::default()).await;
    let data = Data::parse(&mut config);
    let cache = Caches::parse(&mut config);

    let store = core.storage.data.clone();
    let search_store = core.storage.fts.clone();
    let (ipc, mut ipc_rxs) = build_ipc(false);
    let inner = Arc::new(Inner {
        shared_core: core.into_shared(),
        data,
        ipc,
        cache,
    });

    // Parse acceptors
    servers.parse_tcp_acceptors(&mut config, inner.clone());

    // Enable tracing
    tracers.enable(true);

    // Start services
    config.assert_no_errors();
    ipc_rxs.spawn_queue_manager(inner.clone());
    ipc_rxs.spawn_services(inner.clone());

    // Spawn servers
    let (shutdown_tx, _) = servers.spawn(|server, acceptor, shutdown_rx| {
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

    if delete_if_exists {
        store_destroy(&store).await;
        search_store_destroy(&search_store).await;
    }

    // Create test accounts
    let mut clients = AHashMap::new();
    for (account, secret, name, email) in TEST_USERS {
        let account_id = store
            .create_test_user(account, secret, name, &[email])
            .await;
        clients.insert(
            *account,
            DummyWebDavClient::new(account_id, account, secret, email),
        );
        store
            .add_permissions(
                account,
                [Permission::DavPrincipalList, Permission::DavPrincipalSearch],
            )
            .await;
        if *account == "mike" {
            store.set_test_quota(account, 1024).await;
        }
    }
    store
        .create_test_group("support", "Support Group", &["support@example.com"])
        .await;
    store.add_to_group("jane", "support").await;

    WebDavTest {
        server: inner.build_server(),
        clients,
        temp_dir,
        shutdown_tx,
    }
}

impl WebDavTest {
    pub fn client(&self, name: &'static str) -> &DummyWebDavClient {
        self.clients.get(name).unwrap()
    }

    pub async fn resources(&self, name: &'static str, collection: Collection) -> Arc<DavResources> {
        let account_id = self.client(name).account_id;
        let access_token = self.server.get_access_token(account_id).await.unwrap();
        self.server
            .fetch_dav_resources(&access_token, account_id, collection.into())
            .await
            .unwrap()
    }

    pub fn clear_cache(&self) {
        for cache in [
            &self.server.inner.cache.events,
            &self.server.inner.cache.contacts,
            &self.server.inner.cache.files,
        ] {
            cache.clear();
        }
    }

    pub async fn assert_is_empty(&self) {
        assert_is_empty(&self.server).await;
        self.clear_cache();
    }

    pub async fn wait_for_tasks(&self) {
        wait_for_tasks(&self.server).await;
    }
}

pub trait DavResourcesTest {
    fn items(&self) -> Vec<DavResource>;
}

impl DavResourcesTest for DavResources {
    fn items(&self) -> Vec<DavResource> {
        self.resources.clone()
    }
}

pub const TEST_VCARD_1: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:18F098B5-7383-4FD6-B482-48F2181D73AA
X-TEST:SEQ1
N:Coyote;Wile;E.;;
FN:Wile E. Coyote
ORG:ACME Inc.;
END:VCARD
"#;

pub const TEST_VCARD_2: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:6exhjr32bt783wwlr9u0sr8lfqse5x7zqc8y
X-TEST:SEQ1
FN:Joe Citizen
N:Citizen;Joe;;;
NICKNAME:human_being
EMAIL;TYPE=pref:jcitizen@foo.com
REV:20200411T072429Z
END:VCARD
"#;

pub const TEST_ICAL_1: &str = r#"BEGIN:VCALENDAR
SOURCE;VALUE=URI:http://calendar.example.com/event_with_html.ics
X-TEST:SEQ1
BEGIN:VEVENT
UID: 2371c2d9-a136-43b0-bba3-f6ab249ad46e
SUMMARY:What a nice present: 🎁
DTSTART;TZID=America/New_York:20190221T170000
DTEND;TZID=America/New_York:20190221T180000
LOCATION:Germany
DESCRIPTION:<html><body><h1>Title</h1><p><ul><li><b>first</b> Row </li><li><
 i>second</i> Row</li></ul></p></body></html>
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_ICAL_2: &str = r#"BEGIN:VCALENDAR
X-TEST:SEQ1
BEGIN:VEVENT
UID:0000001
SUMMARY:Treasure Hunting
DTSTART;TZID=America/Los_Angeles:20150706T120000
DTEND;TZID=America/Los_Angeles:20150706T130000
RRULE:FREQ=DAILY;COUNT=10
EXDATE;TZID=America/Los_Angeles:20150708T120000
EXDATE;TZID=America/Los_Angeles:20150710T120000
END:VEVENT
BEGIN:VEVENT
UID:0000001
SUMMARY:More Treasure Hunting
LOCATION:The other island
DTSTART;TZID=America/Los_Angeles:20150709T150000
DTEND;TZID=America/Los_Angeles:20150707T160000
RECURRENCE-ID;TZID=America/Los_Angeles:20150707T120000
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_FILE_1: &str = r#"this is a test file
with some text
and some more text

X-TEST:SEQ1
"#;

pub const TEST_FILE_2: &str = r#"another test file
with amazing content
and some more text

X-TEST:SEQ1
"#;

pub const TEST_VTIMEZONE_1: &str = r#"BEGIN:VCALENDAR
PRODID:-//Example Corp.//CalDAV Client//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:US-Eastern
LAST-MODIFIED:19870101T000000Z
BEGIN:STANDARD
DTSTART:19671029T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
TZNAME:Eastern Standard Time (US Canada)
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19870405T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
TZNAME:Eastern Daylight Time (US Canada)
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
"#;

impl WebDavTest {
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
}

const SERVER: &str = r#"
[server]
hostname = "webdav.example.org"

[spam-filter]
enable = false

[http]
url = "'https://127.0.0.1:8899'"

[server.listener.webdav]
bind = ["127.0.0.1:8899"]
protocol = "http"
max-connections = 81920
tls.implicit = true

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = "default"

[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = [ { if = "!is_empty(authenticated_as)", then = true }, 
        { else = false } ]

[session.rcpt.errors]
total = 5
wait = "1ms"

[resolver]
type = "system"

[queue.strategy]
route = [ { if = "rcpt_domain == 'example.com'", then = "'local'" }, 
            { else = "'mx'" } ]

[session.data.add-headers]
delivered-to = false

[session.extensions]
future-release = [ { if = "!is_empty(authenticated_as)", then = "99999999d"},
                { else = false } ]

[certificate.default]
cert = "%{file:{CERT}}%"
private-key = "%{file:{PK}}%"

[jmap.protocol]
set.max-objects = 100000

[jmap.protocol.request]
max-concurrent = 8

[jmap.protocol.upload]
max-size = 5000000
max-concurrent = 4
ttl = "1m"

[jmap.protocol.upload.quota]
files = 3
size = 50000

[jmap.rate-limit]
account = "1000/1m"
authentication = "100/2s"
anonymous = "100/1m"

[calendar.alarms]
minimum-interval = "1s"

[calendar.scheduling.inbound]
auto-add = true

[dav.collection]
assisted-discovery = {ASSISTED_DISCOVERY}

[sharing]
allow-directory-query = true

[store."auth"]
type = "sqlite"
path = "{TMP}/auth.db"

[store."auth".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = ? AND active = true"
members = "SELECT member_of FROM group_members WHERE name = ?"
recipients = "SELECT name FROM emails WHERE address = ?"
emails = "SELECT address FROM emails WHERE name = ? AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE '%' || ? || '%' AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = ? AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE '%@' || ? LIMIT 1"

[oauth]
key = "parerga_und_paralipomena"

[oauth.auth]
max-attempts = 1

[oauth.expiry]
user-code = "1s"
token = "1s"
refresh-token = "3s"
refresh-token-renew = "2s"

[tracer.console]
type = "console"
level = "{LEVEL}"
multiline = false
ansi = true
disabled-events = ["network.*"]
 
"#;
