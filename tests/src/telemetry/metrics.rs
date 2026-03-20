/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::telemetry::metrics::store::{MetricsStore, SharedMetricHistory};
use registry::{schema::prelude::ObjectType, types::datetime::UTCDateTime};
use std::time::Duration;
use store::{
    rand::{self, Rng},
    write::now,
};
use trc::*;
use types::id::Id;

pub async fn test(test: &TestServer) {
    println!("Running Metrics tests...");

    // Make sure there are no span entries in the db
    let admin = test.account("admin@example.org");
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Metric,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );

    // Insert test metrics
    insert_test_metrics(test).await;

    // Fetch all metrics
    let metric_ids = admin
        .registry_query(
            ObjectType::Metric,
            Vec::<(&str, &str)>::new(),
            Vec::<&str>::new(),
        )
        .await
        .object_ids()
        .collect::<Vec<_>>();
    let response = admin
        .registry_get_many(ObjectType::Metric, Vec::<&str>::new())
        .await;
    let metrics = response.list();
    assert!(
        metrics.len() > 2000,
        "Found {} metrics, expected more than 2000",
        metrics.len()
    );
    assert_eq!(metrics.len(), metric_ids.len());

    // Fetch the last 48 hours of metrics
    let metric_ids = admin
        .registry_query(
            ObjectType::Metric,
            [(
                "timestampIsGreaterThan",
                UTCDateTime::from_timestamp((now() - (2 * 86400)) as i64).to_string(),
            )],
            Vec::<&str>::new(),
        )
        .await
        .object_ids()
        .collect::<Vec<_>>();
    assert!(
        metric_ids.len() > 20 && metric_ids.len() < 2000,
        "Found {} metrics, expected more than 20 and less than 2000",
        metric_ids.len()
    );

    // Purge metrics and make sure they are gone
    test.server
        .metrics_store()
        .purge_metrics(Duration::from_secs(0))
        .await
        .unwrap();
    assert_eq!(
        admin
            .registry_query(
                ObjectType::Metric,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>(),
        Vec::<Id>::new()
    );
}

async fn insert_test_metrics(test: &TestServer) {
    test.server
        .metrics_store()
        .purge_metrics(Duration::from_secs(0))
        .await
        .unwrap();
    let mut start_time = now() - (90 * 24 * 60 * 60);
    let timestamp = now();
    let history = SharedMetricHistory::default();

    while start_time < timestamp {
        for event_type in [
            EventType::Smtp(SmtpEvent::ConnectionStart),
            EventType::Imap(ImapEvent::ConnectionStart),
            EventType::Pop3(Pop3Event::ConnectionStart),
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
            EventType::Http(HttpEvent::ConnectionStart),
            EventType::Delivery(DeliveryEvent::AttemptStart),
            EventType::Queue(QueueEvent::MessageQueued),
            EventType::Queue(QueueEvent::AuthenticatedMessageQueued),
            EventType::Queue(QueueEvent::DsnQueued),
            EventType::Queue(QueueEvent::ReportQueued),
            EventType::MessageIngest(MessageIngestEvent::Ham),
            EventType::MessageIngest(MessageIngestEvent::Spam),
            EventType::Auth(AuthEvent::Failed),
            EventType::Security(SecurityEvent::AuthenticationBan),
            EventType::Security(SecurityEvent::ScanBan),
            EventType::Security(SecurityEvent::AbuseBan),
            EventType::Security(SecurityEvent::LoiterBan),
            EventType::Security(SecurityEvent::IpBlocked),
            EventType::IncomingReport(IncomingReportEvent::DmarcReport),
            EventType::IncomingReport(IncomingReportEvent::DmarcReportWithWarnings),
            EventType::IncomingReport(IncomingReportEvent::TlsReport),
            EventType::IncomingReport(IncomingReportEvent::TlsReportWithWarnings),
        ] {
            // Generate a random value between 0 and 100
            Collector::update_event_counter(event_type, rand::rng().random_range(0..=100))
        }

        Collector::update_gauge(MetricType::QueueCount, rand::rng().random_range(0..=1000));
        Collector::update_gauge(
            MetricType::ServerMemory,
            rand::rng().random_range(100 * 1024 * 1024..=300 * 1024 * 1024),
        );

        for metric_type in [
            MetricType::MessageIngestTime,
            MetricType::MessageIngestIndexTime,
            MetricType::DeliveryTotalTime,
            MetricType::DnsLookupTime,
        ] {
            Collector::update_histogram(metric_type, rand::rng().random_range(2..=1000))
        }
        Collector::update_histogram(
            MetricType::DeliveryTotalTime,
            rand::rng().random_range(1000..=5000),
        );

        test.server
            .metrics_store()
            .write_metrics(start_time.into(), history.clone())
            .await
            .unwrap();
        start_time += 60 * 60 * 24;
    }
}
