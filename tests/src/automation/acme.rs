/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::network::dns::update::DNS_RECORDS;
use dns_update::DnsRecord;
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{AcmeChallengeType, AcmeRenewBefore, DnsRecordType},
        prelude::{ObjectType, Property},
        structs::{
            AcmeProvider, Certificate, CertificateManagement, CertificateManagementProperties,
            DkimManagement, DnsManagement, DnsManagementProperties, DnsServer, DnsServerCloudflare,
            Domain, SecretKey, SecretKeyValue, Task, TaskDomainManagement,
        },
    },
    types::map::Map,
};
use serde_json::json;

pub async fn test(test: &TestServer) {
    println!("Running ACME tests...");
    let account = test.account("admin@example.org");

    // Create test Pebble and In Memory DNS servers
    let pebble_dns_id = account
        .registry_create_object(DnsServer::Cloudflare(DnsServerCloudflare {
            email: "test@pebble.org".to_string().into(),
            secret: SecretKey::Value(SecretKeyValue {
                secret: "secret".into(),
            }),
            ..Default::default()
        }))
        .await;
    let in_memory_dns_id = account
        .registry_create_object(DnsServer::Cloudflare(DnsServerCloudflare {
            email: "test@memory.org".to_string().into(),
            secret: SecretKey::Value(SecretKeyValue {
                secret: "secret".into(),
            }),
            ..Default::default()
        }))
        .await;

    // ACME provider creation should fail without a contact email
    account
        .registry_create_object_expect_err(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            ..Default::default()
        })
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_description_contains("At least one contact email is required");

    // Create an ACME provider using TLS-ALPN-01 challenge
    let tls_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@tls.org".to_string()]),
            challenge_type: AcmeChallengeType::TlsAlpn01,
            renew_before: AcmeRenewBefore::R12,
            ..Default::default()
        })
        .await;
    let provider = account.registry_get::<AcmeProvider>(tls_acme_id).await;
    assert_eq!(provider.directory, "https://localhost:14000/dir");
    assert_eq!(
        provider.contact,
        Map::new(vec!["mailto:hello@tls.org".to_string()])
    );
    assert!(
        provider.account_uri.starts_with("https://localhost:14000"),
        "Provider {:?} has invalid account URI",
        provider
    );

    // Create a domain and trigger TLS-ALPN-01 ACME renewal
    let domain_id = account
        .registry_create_object(Domain {
            name: "tls.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: tls_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: in_memory_dns_id,
                publish_records: Map::new(vec![
                    DnsRecordType::Tlsa,
                    DnsRecordType::AutoConfig,
                    DnsRecordType::AutoConfigLegacy,
                    DnsRecordType::AutoDiscover,
                    DnsRecordType::MtaSts,
                ]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(
        sans,
        vec![
            "autoconfig.tls.org".to_string(),
            "autodiscover.tls.org".to_string(),
            "mta-sts.tls.org".to_string(),
            "ua-auto-config.tls.org".to_string()
        ]
    );

    // Make sure the TLSA records were added to the in-memory DNS server
    let records = DNS_RECORDS.lock().unwrap().clone();
    for record in [
        "_443._tcp.mta-sts.tls.org.",
        "_443._tcp.autoconfig.tls.org.",
        "_443._tcp.ua-auto-config.tls.org.",
        "_443._tcp.autodiscover.tls.org.",
    ] {
        if records
            .iter()
            .find(|r| r.name == record && matches!(r.record, DnsRecord::TLSA(_)))
            .is_none()
        {
            panic!(
                "Expected TLSA record for {} not found in DNS records: {:?}",
                record, records
            );
        }
    }

    // Make sure a task was created to renew the certificate before it expires
    let tasks = account.registry_get_all::<Task>().await;
    assert_eq!(
        tasks.len(),
        1,
        "Expected 1 task, found {}: {:?}",
        tasks.len(),
        tasks
    );
    let task = tasks.into_iter().next().unwrap().1;
    if let Task::AcmeRenewal(TaskDomainManagement {
        domain_id: task_domain_id,
        ..
    }) = task
    {
        assert_eq!(
            task_domain_id, domain_id,
            "ACME renewal task has incorrect domain ID"
        );
    } else {
        panic!("Expected ACME renewal task, found: {:?}", task);
    }
    let not_valid_after = certificate.not_valid_after.timestamp();
    let not_valid_before = certificate.not_valid_before.timestamp();
    let length = not_valid_after - not_valid_before;
    assert_eq!(
        not_valid_after - length / 2,
        task.due_timestamp() as i64,
        "ACME renewal task has incorrect due timestamp, expected around {} but found {}",
        not_valid_after - length / 2,
        task.due_timestamp() as i64
    );
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;

    // Test ACME using HTTP-01 challenge and the server domain "mail.example.org"
    let http_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@example.org".to_string()]),
            challenge_type: AcmeChallengeType::Http01,
            ..Default::default()
        })
        .await;
    let domain_id = account.find_or_create_domain("example.org").await;
    account.registry_update_object(ObjectType::Domain, domain_id, json!({
        Property::CertificateManagement: CertificateManagement::Automatic(CertificateManagementProperties {
            acme_provider_id: http_acme_id,
            subject_alternative_names: Default::default(),
        }),
    })).await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(
        sans,
        vec![
            "autoconfig.example.org".to_string(),
            "autodiscover.example.org".to_string(),
            "imap.example.org".to_string(),
            "mail.example.org".to_string(),
            "mta-sts.example.org".to_string(),
            "mx1.example.org".to_string(),
            "mx2.example.org".to_string(),
            "pop3.example.org".to_string(),
            "smtp.example.org".to_string(),
            "ua-auto-config.example.org".to_string()
        ]
    );
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;

    // Test ACME using DNS-01 challenge
    let dns_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@dns.org".to_string()]),
            challenge_type: AcmeChallengeType::Dns01,
            ..Default::default()
        })
        .await;
    account
        .registry_create_object(Domain {
            name: "dns.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: dns_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: pebble_dns_id,
                publish_records: Map::new(vec![DnsRecordType::Caa]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(sans, vec!["*.dns.org".to_string()]);
    account.registry_destroy_all(ObjectType::Certificate).await;
    account.registry_destroy_all(ObjectType::Task).await;

    // Test ACME using DNS-01 challenge
    let dns_acme_id = account
        .registry_create_object(AcmeProvider {
            directory: "https://localhost:14000/dir".to_string(),
            contact: Map::new(vec!["mailto:hello@persist.org".to_string()]),
            challenge_type: AcmeChallengeType::DnsPersist01,
            ..Default::default()
        })
        .await;
    account
        .registry_create_object(Domain {
            name: "persist.org".to_string(),
            certificate_management: CertificateManagement::Automatic(
                CertificateManagementProperties {
                    acme_provider_id: dns_acme_id,
                    subject_alternative_names: Default::default(),
                },
            ),
            dkim_management: DkimManagement::Manual,
            dns_management: DnsManagement::Automatic(DnsManagementProperties {
                dns_server_id: pebble_dns_id,
                publish_records: Map::new(vec![DnsRecordType::Caa]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    test.wait_for_tasks_skip_not_due().await;
    let certificate = account
        .registry_get_all::<Certificate>()
        .await
        .into_iter()
        .next()
        .unwrap()
        .1;
    let mut sans = certificate.subject_alternative_names.into_inner();
    sans.sort();
    assert_eq!(sans, vec!["*.persist.org".to_string()]);
}
