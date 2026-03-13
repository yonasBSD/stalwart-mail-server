/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod blob;
pub mod import_export;
pub mod lookup;
pub mod ops;
pub mod query;
pub mod registry;

use crate::utils::server::TestServerBuilder;
use std::io::Read;

pub struct TempDir {
    pub path: std::path::PathBuf,
}

#[tokio::test(flavor = "multi_thread")]
pub async fn store_tests() {
    let test = TestServerBuilder::new("store_tests").await.build().await;

    println!("Testing store {}...", std::env::var("STORE").unwrap());

    test.destroy_store().await;

    registry::test(&test).await;
    import_export::test(&test).await;
    ops::test(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

#[tokio::test(flavor = "multi_thread")]
pub async fn search_tests() {
    let test = TestServerBuilder::new("search_store_tests")
        .await
        .build()
        .await;

    println!(
        "Testing search store {}...",
        std::env::var("SEARCH_STORE").unwrap_or("default".to_string())
    );

    query::test(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

pub fn deflate_test_resource(name: &str) -> Vec<u8> {
    let mut csv_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    csv_path.push("resources");
    csv_path.push(name);

    let mut decoder = flate2::bufread::GzDecoder::new(std::io::BufReader::new(
        std::fs::File::open(csv_path).unwrap(),
    ));
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).unwrap();
    result
}

impl TempDir {
    pub fn new(name: &str, delete_if_exists: bool) -> Self {
        let mut path = std::env::temp_dir();
        path.push(name);
        if delete_if_exists && path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn delete(&self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}
