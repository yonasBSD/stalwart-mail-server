/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::{TestMessage, TestQueueEvent, TestReportingEvent},
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use common::{
    config::smtp::resolver::{Tlsa, TlsaEntry, TlsaMatching},
    ipc::PolicyType,
};
use mail_auth::{
    MX,
    common::parse::TxtRecordParser,
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::ResultType,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PublicKeyData, date_time_ymd,
};
use registry::schema::{
    enums::MtaRequiredOrOptional,
    prelude::ObjectType,
    structs::{Expression, MtaTlsStrategy, TlsReportSettings},
};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use smtp::outbound::dane::{dnssec::TlsaLookup, verify::TlsaVerify};
use smtp::queue::{Error, ErrorDetails, Status};
use store::write::now;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    num::ParseIntError,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[tokio::test]
#[serial_test::serial]
async fn dane_verify() {
    let mut local = TestServerBuilder::new("smtp_dane_local")
        .await
        .with_http_listener(19018)
        .await
        .disable_services()
        .capture_queue()
        .capture_reporting()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_dane_remote")
        .await
        .with_dummy_tls_cert(["*.foobar.org"])
        .await
        .with_http_listener(19019)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    local_admin
        .registry_create_object(TlsReportSettings {
            send_frequency: Expression {
                else_: "weekly".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let (tls_strategy_id, mut tls_strategy) = local_admin
        .registry_get_all::<MtaTlsStrategy>()
        .await
        .into_iter()
        .find(|(_, s)| s.name == "default")
        .unwrap();
    tls_strategy.dane = MtaRequiredOrOptional::Require;
    tls_strategy.start_tls = MtaRequiredOrOptional::Require;
    let mut tls_strategy = serde_json::to_value(tls_strategy).unwrap();
    tls_strategy
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "name");
    local_admin
        .registry_update_object(ObjectType::MtaTlsStrategy, tls_strategy_id, tls_strategy)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_add_all_headers().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Add mock DNS entries
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );
    local.server.txt_add(
        "_smtp._tls.foobar.org",
        TlsRpt::parse(b"v=TLSRPTv1; rua=mailto:reports@foobar.org").unwrap(),
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No TLSA reco=")
        .assert_contains("rds found");
    local.read_event().await.assert_done();
    local.assert_no_events();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.domain, "foobar.org");
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DaneRequired
    );
    assert_eq!(
        report.failure.as_ref().unwrap().receiving_mx_hostname,
        Some("mx.foobar.org".to_string())
    );
    assert_eq!(
        report.tls_record.rua,
        vec![ReportUri::Mail("reports@foobar.org".to_string())]
    );

    // DANE failure with no matching certificates
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_spki: true,
            matching: TlsaMatching::Sha256,
            data: vec![1, 2, 3],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    local.server.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate")
        .assert_contains("No matching ")
        .assert_contains("certificates found");
    local.read_event().await.assert_done();
    local.assert_no_events();

    // Expect TLS failure report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::ValidationFailure
    );
    remote.assert_no_events();

    // DANE successful delivery
    let tlsa = Arc::new(Tlsa {
        entries: vec![TlsaEntry {
            is_end_entity: true,
            is_spki: true,
            matching: TlsaMatching::Sha256,
            data: vec![
                73, 186, 44, 106, 13, 198, 100, 180, 0, 44, 158, 188, 15, 195, 39, 198, 61, 254,
                215, 237, 100, 26, 15, 155, 219, 235, 120, 64, 128, 172, 17, 0,
            ],
        }],
        has_end_entities: true,
        has_intermediates: false,
    });
    local.server.tlsa_add(
        "_25._tcp.mx.foobar.org",
        tlsa.clone(),
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local.read_event().await.assert_done();
    local.assert_no_events();
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_contains("using TLSv1.3 with cipher");

    // Expect TLS success report
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(tlsa.into()));
    assert!(report.failure.is_none());

    // An insecure (non-DNSSEC) MX zone must not honor TLSA records,
    // even when valid records are cached.
    local.server.dnssec_add(
        "mx.foobar.org",
        false,
        Instant::now() + Duration::from_secs(10),
    );
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());
    local
        .expect_message()
        .await
        .read_lines(&local)
        .await
        .assert_contains("<bill@foobar.org> (DANE failed to authenticate");
    local.read_event().await.assert_done();
    local.assert_no_events();
    let report = local.read_report().await.unwrap_tls();
    assert_eq!(report.policy, PolicyType::Tlsa(None));
    assert_eq!(
        report.failure.as_ref().unwrap().result_type,
        ResultType::DaneRequired
    );
    remote.assert_no_events();
}

#[tokio::test]
#[serial_test::serial]
async fn dane_downgrade_on_tlsa_servfail() {
    let mut local = TestServerBuilder::new("smtp_dane_downgrade_local")
        .await
        .with_http_listener(19020)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_dane_downgrade_remote")
        .await
        .with_dummy_tls_cert(["*.foobar.org"])
        .await
        .with_http_listener(19021)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_no_auth().await;
    let (tls_strategy_id, mut tls_strategy) = local_admin
        .registry_get_all::<MtaTlsStrategy>()
        .await
        .into_iter()
        .find(|(_, s)| s.name == "default")
        .unwrap();
    tls_strategy.dane = MtaRequiredOrOptional::Optional;
    tls_strategy.start_tls = MtaRequiredOrOptional::Require;
    tls_strategy.allow_invalid_certs = true;
    let mut tls_strategy = serde_json::to_value(tls_strategy).unwrap();
    tls_strategy
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k != "name");
    local_admin
        .registry_update_object(ObjectType::MtaTlsStrategy, tls_strategy_id, tls_strategy)
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_add_all_headers().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx._dns_error.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx._dns_error.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());

    let retry = local.expect_message().await;
    assert!(retry.message.recipients[0].retry.due > now());
    remote.assert_no_events();
}

#[tokio::test]
async fn dane_test() {
    let test = TestServerBuilder::new("smtp_dane_remote")
        .await
        .with_http_listener(19036)
        .await
        .disable_services()
        .build()
        .await;

    // Add dns entries
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("smtp");
    path.push("dane");
    let mut file = path.clone();
    file.push("dns.txt");

    let mut hosts = BTreeSet::new();
    let mut tlsa = Tlsa {
        entries: Vec::new(),
        has_end_entities: false,
        has_intermediates: false,
    };
    let mut hostname = String::new();

    for line in BufReader::new(File::open(file).unwrap()).lines() {
        let line = line.unwrap();
        let mut is_end_entity = false;
        for (pos, item) in line.split_whitespace().enumerate() {
            match pos {
                0 => {
                    if hostname != item && !hostname.is_empty() {
                        test.server.tlsa_add(
                            hostname,
                            tlsa.into(),
                            Instant::now() + Duration::from_secs(30),
                        );
                        tlsa = Tlsa {
                            entries: Vec::new(),
                            has_end_entities: false,
                            has_intermediates: false,
                        };
                    }
                    hosts.insert(item.strip_prefix("_25._tcp.").unwrap().to_string());
                    hostname = item.to_string();
                }
                1 => {
                    is_end_entity = item == "3";
                }
                4 => {
                    if is_end_entity {
                        tlsa.has_end_entities = true;
                    } else {
                        tlsa.has_intermediates = true;
                    }
                    tlsa.entries.push(TlsaEntry {
                        is_end_entity,
                        is_spki: true,
                        matching: TlsaMatching::Sha256,
                        data: decode_hex(item).unwrap(),
                    });
                }
                _ => (),
            }
        }
    }
    test.server.tlsa_add(
        hostname,
        tlsa.into(),
        Instant::now() + Duration::from_secs(30),
    );

    // Add certificates
    assert!(!hosts.is_empty());
    for host in hosts {
        // Add certificates
        let mut certs = Vec::new();
        for num in 0..6 {
            let mut file = path.clone();
            file.push(format!("{host}.{num}.cert"));
            if file.exists() {
                certs.push(CertificateDer::from(fs::read(file).unwrap()));
            } else {
                break;
            }
        }

        // Successful DANE verification (end-entity match, RFC 7671 Section 5.1)
        let tlsa = test
            .server
            .tlsa_lookup(format!("_25._tcp.{host}."))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            tlsa.verify(0, &host, &[host.as_str()], Some(&certs)),
            Ok(())
        );

        // Failed DANE verification
        certs.remove(0);
        assert_eq!(
            tlsa.verify(0, &host, &[host.as_str()], Some(&certs)),
            Err(Status::PermanentFailure(ErrorDetails {
                entity: host.into(),
                details: Error::DaneError("No matching certificates found in TLSA records".into())
            }))
        );
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    der: CertificateDer<'static>,
    spki: Vec<u8>,
}

#[test]
fn dane_ee_matches_leaf_ignoring_name() {
    let root = root_ca("EE Root");
    let intermediate = sub_ca("EE Intermediate", &root);
    let (leaf_der, leaf_spki) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone()];

    let record = tlsa(vec![ee_spki_sha256(&leaf_spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["name.mismatch.example"], Some(&chain))
            .is_ok()
    );

    let wrong = tlsa(vec![ee_spki_sha256(&root.spki)]);
    assert!(
        wrong
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ee_ignores_expiration() {
    let root = root_ca("Expired EE Root");
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["mx.foobar.org".to_string()]).unwrap();
    params.not_before = date_time_ymd(2018, 1, 1);
    params.not_after = date_time_ymd(2021, 1, 1);
    params
        .distinguished_name
        .push(DnType::CommonName, "mx.foobar.org");
    let leaf = params.signed_by(&key, &root.issuer).unwrap();
    let leaf_spki = key.subject_public_key_info();
    let chain = vec![leaf.der().clone()];

    let record = tlsa(vec![ee_spki_sha256(&leaf_spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_anchors_at_private_intermediate() {
    let root = root_ca("TA Private Root");
    let intermediate = sub_ca("TA Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_matches_when_ee_present_but_unmatched() {
    let root = root_ca("Mixed Root");
    let intermediate = sub_ca("Mixed Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![
        ee_spki_sha256(&root.spki),
        ta_full_sha256(&intermediate.der),
    ]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );
}

#[test]
fn dane_ta_requires_name_match() {
    let root = root_ca("Name Root");
    let intermediate = sub_ca("Name Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&intermediate.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["other.example"], Some(&chain))
            .is_err()
    );
    assert!(
        record
            .verify(
                0,
                "mx.foobar.org",
                &["other.example", "mx.foobar.org"],
                Some(&chain)
            )
            .is_ok()
    );
}

#[test]
fn dane_ta_rejects_unrelated_ca_matching_hash() {
    let root = root_ca("Forgery Root");
    let intermediate = sub_ca("Forgery Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let unrelated = root_ca("Unrelated CA");
    let chain = vec![leaf_der, intermediate.der.clone(), unrelated.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&unrelated.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ta_rejects_expired_intermediate() {
    let root = root_ca("Validity Root");
    let int_key = KeyPair::generate().unwrap();
    let mut int_params = ca_params("Expired Intermediate");
    int_params.not_before = date_time_ymd(2018, 1, 1);
    int_params.not_after = date_time_ymd(2021, 1, 1);
    let int_cert = int_params.signed_by(&int_key, &root.issuer).unwrap();
    let intermediate = TestCa {
        der: int_cert.der().clone(),
        spki: int_key.subject_public_key_info(),
        issuer: Issuer::new(int_params, int_key),
    };
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone(), root.der.clone()];

    let record = tlsa(vec![ta_full_sha256(&root.der)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

#[test]
fn dane_ta_bare_key_anchors_chain() {
    let root = root_ca("Bare Key Root");
    let intermediate = sub_ca("Bare Key Intermediate", &root);
    let (leaf_der, _) = leaf_cert("mx.foobar.org", &intermediate);
    let chain = vec![leaf_der, intermediate.der.clone()];

    let record = tlsa(vec![ta_spki_full(&root.spki)]);
    assert!(
        record
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_ok()
    );

    let unrelated = root_ca("Bare Key Unrelated");
    let wrong = tlsa(vec![ta_spki_full(&unrelated.spki)]);
    assert!(
        wrong
            .verify(0, "mx.foobar.org", &["mx.foobar.org"], Some(&chain))
            .is_err()
    );
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn root_ca(common_name: &str) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(common_name);
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().clone();
    let spki = key.subject_public_key_info();
    TestCa {
        issuer: Issuer::new(params, key),
        der,
        spki,
    }
}

fn sub_ca(common_name: &str, parent: &TestCa) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let params = ca_params(common_name);
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    let der = cert.der().clone();
    let spki = key.subject_public_key_info();
    TestCa {
        issuer: Issuer::new(params, key),
        der,
        spki,
    }
}

fn leaf_cert(san: &str, parent: &TestCa) -> (CertificateDer<'static>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![san.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, san);
    let cert = params.signed_by(&key, &parent.issuer).unwrap();
    (cert.der().clone(), key.subject_public_key_info())
}

fn ee_spki_sha256(spki: &[u8]) -> TlsaEntry {
    TlsaEntry {
        is_end_entity: true,
        is_spki: true,
        matching: TlsaMatching::Sha256,
        data: Sha256::digest(spki).to_vec(),
    }
}

fn ta_full_sha256(der: &CertificateDer<'_>) -> TlsaEntry {
    TlsaEntry {
        is_end_entity: false,
        is_spki: false,
        matching: TlsaMatching::Sha256,
        data: Sha256::digest(der.as_ref()).to_vec(),
    }
}

fn ta_spki_full(spki: &[u8]) -> TlsaEntry {
    TlsaEntry {
        is_end_entity: false,
        is_spki: true,
        matching: TlsaMatching::Full,
        data: spki.to_vec(),
    }
}

fn tlsa(entries: Vec<TlsaEntry>) -> Tlsa {
    Tlsa {
        has_end_entities: entries.iter().any(|entry| entry.is_end_entity),
        has_intermediates: entries.iter().any(|entry| !entry.is_end_entity),
        entries,
    }
}
