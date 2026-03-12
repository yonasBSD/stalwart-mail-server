/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::{
        enums::{BlobStoreType, DataStoreType, InMemoryStoreType, SearchStoreType},
        prelude::Object,
        structs::{
            BlobStore, DataStore, ElasticSearchStore, FileSystemStore, FoundationDbStore, HttpAuth,
            HttpAuthBasic, InMemoryStore, MeilisearchStore, MySqlStore, PostgreSqlStore,
            RedisStore, RocksDbStore, S3Store, S3StoreCustomRegion, S3StoreRegion, SearchStore,
            SecretKey, SecretKeyOptional, SecretKeyValue, SqliteStore,
        },
    },
    types::{EnumImpl, duration::Duration},
};
use store::{
    RegistryStore,
    registry::write::{RegistryWrite, RegistryWriteResult},
};
use types::id::Id;

pub trait RegistryEnvStores {
    fn insert_stores_from_env(&self) -> impl Future<Output = ()>;
}

impl RegistryEnvStores for RegistryStore {
    async fn insert_stores_from_env(&self) {
        let path = self.path().as_os_str().to_str().unwrap();
        let search_store = std::env::var("SEARCH_STORE")
            .map(|store| SearchStoreType::parse(&store).expect("Invalid store type"))
            .map(|store| build_search_store(store, path))
            .map(Object::from)
            .ok();
        let blob_store = std::env::var("BLOB_STORE")
            .map(|store| BlobStoreType::parse(&store).expect("Invalid store type"))
            .map(|store| build_blob_store(store, path))
            .map(Object::from)
            .ok();
        let in_memory = std::env::var("MEMORY_STORE")
            .map(|store| InMemoryStoreType::parse(&store).expect("Invalid store type"))
            .map(|store| build_in_memory_store(store, path))
            .map(Object::from)
            .ok();

        for store in [search_store, blob_store, in_memory].into_iter().flatten() {
            self.write(RegistryWrite::insert(&store))
                .await
                .expect("Failed to insert store into registry")
                .unwrap_id(trc::location!());
        }
    }
}

pub fn build_data_store(typ: DataStoreType, path: &str) -> DataStore {
    match typ {
        DataStoreType::RocksDb => DataStore::RocksDb(RocksDbStore {
            path: format!("{path}/rocks.db"),
            ..Default::default()
        }),
        DataStoreType::Sqlite => DataStore::Sqlite(SqliteStore {
            path: format!("{path}/sqlite.db"),
            ..Default::default()
        }),
        DataStoreType::FoundationDb => DataStore::FoundationDb(FoundationDbStore::default()),
        DataStoreType::PostgreSql => DataStore::PostgreSql(PostgreSqlStore {
            host: "localhost".into(),
            port: 5432,
            auth_username: "postgres".to_string().into(),
            auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                secret: "mysecretpassword".into(),
            }),
            database: "stalwart".into(),
            use_tls: false,
            allow_invalid_certs: true,
            ..Default::default()
        }),
        DataStoreType::MySql => DataStore::MySql(MySqlStore {
            host: "localhost".into(),
            port: 3307,
            auth_username: "root".to_string().into(),
            auth_secret: SecretKeyOptional::Value(SecretKeyValue {
                secret: "password".into(),
            }),
            database: "stalwart".into(),
            use_tls: false,
            allow_invalid_certs: true,
            ..Default::default()
        }),
    }
}

fn build_blob_store(typ: BlobStoreType, path: &str) -> BlobStore {
    match typ {
        BlobStoreType::S3 => BlobStore::S3(S3Store {
            access_key: "minioadmin".to_string().into(),
            bucket: "tmp".into(),
            region: S3StoreRegion::Custom(S3StoreCustomRegion {
                custom_endpoint: "http://localhost:9000".into(),
                custom_region: "eu-central-1".into(),
            }),
            secret_key: SecretKeyOptional::Value(SecretKeyValue {
                secret: "minioadmin".into(),
            }),
            allow_invalid_certs: true,
            ..Default::default()
        }),
        BlobStoreType::FileSystem => BlobStore::FileSystem(FileSystemStore {
            path: path.to_string(),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
}

fn build_in_memory_store(typ: InMemoryStoreType, _path: &str) -> InMemoryStore {
    match typ {
        InMemoryStoreType::Redis => InMemoryStore::Redis(RedisStore {
            url: "redis://127.0.0.1".into(),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
}

fn build_search_store(typ: SearchStoreType, _path: &str) -> SearchStore {
    match typ {
        SearchStoreType::ElasticSearch => SearchStore::ElasticSearch(ElasticSearchStore {
            url: "https://localhost:9200".into(),
            allow_invalid_certs: true,
            http_auth: HttpAuth::Basic(HttpAuthBasic {
                username: "elastic".into(),
                secret: SecretKey::Value(SecretKeyValue {
                    secret: "changeme".into(),
                }),
            }),
            ..Default::default()
        }),
        SearchStoreType::Meilisearch => SearchStore::Meilisearch(MeilisearchStore {
            url: "http://localhost:7700".into(),
            allow_invalid_certs: true,
            poll_interval: Duration::from_millis(100),
            ..Default::default()
        }),
        _ => unreachable!(),
    }
}

pub trait UnwrapRegistryId {
    fn unwrap_id(self, location: &str) -> Id;
}

impl UnwrapRegistryId for RegistryWriteResult {
    fn unwrap_id(self, location: &str) -> Id {
        match self {
            RegistryWriteResult::Success(id) => id,
            err => panic!("Expected success at {location} but got {err}"),
        }
    }
}
