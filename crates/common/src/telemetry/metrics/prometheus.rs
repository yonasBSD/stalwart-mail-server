/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use prometheus::{
    TextEncoder,
    proto::{Bucket, Counter, Gauge, Histogram, Metric, MetricFamily, MetricType},
};
use trc::{Collector, atomics::histogram::AtomicHistogram};

use crate::Server;

impl Server {
    pub async fn export_prometheus_metrics(&self) -> trc::Result<String> {
        let mut metrics = Vec::new();

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let is_enterprise = self.is_enterprise_edition();
        // SPDX-SnippetEnd

        #[cfg(not(feature = "enterprise"))]
        let is_enterprise = false;

        // Add counters
        for counter in Collector::collect_counters(is_enterprise) {
            let mut metric = MetricFamily::default();
            metric.set_name(metric_name(counter.id().name()));
            metric.set_help(counter.id().description().into());
            metric.set_field_type(MetricType::COUNTER);
            metric.set_metric(vec![new_counter(counter.value())]);
            metrics.push(metric);
        }

        // Add gauges
        for gauge in Collector::collect_gauges(is_enterprise) {
            let mut metric = MetricFamily::default();
            metric.set_name(metric_name(gauge.id().name()));
            metric.set_help(gauge.id().description().into());
            metric.set_field_type(MetricType::GAUGE);
            metric.set_metric(vec![new_gauge(gauge.get())]);
            metrics.push(metric);
        }

        // Add histograms
        for histogram in Collector::collect_histograms(is_enterprise) {
            let mut metric = MetricFamily::default();
            metric.set_name(metric_name(histogram.id().name()));
            metric.set_help(histogram.id().description().into());
            metric.set_field_type(MetricType::HISTOGRAM);
            metric.set_metric(vec![new_histogram(histogram)]);
            metrics.push(metric);
        }

        TextEncoder::new().encode_to_string(&metrics).map_err(|e| {
            trc::EventType::Telemetry(trc::TelemetryEvent::OtelExporterError).reason(e)
        })
    }
}

fn metric_name(id: impl AsRef<str>) -> String {
    let id = id.as_ref();
    let mut name = String::with_capacity(id.len());
    for c in id.chars() {
        if c.is_ascii_alphanumeric() {
            name.push(c);
        } else {
            name.push('_');
        }
    }
    name
}

fn new_counter(value: u64) -> Metric {
    let mut m = Metric::default();
    let mut counter = Counter::default();
    counter.set_value(value as f64);
    m.set_counter(counter);
    m
}

fn new_gauge(value: u64) -> Metric {
    let mut m = Metric::default();
    let mut gauge = Gauge::default();
    gauge.set_value(value as f64);
    m.set_gauge(gauge);
    m
}

fn new_histogram(histogram: &AtomicHistogram<12>) -> Metric {
    let mut m = Metric::default();
    let mut h = Histogram::default();
    h.set_sample_count(histogram.count());
    h.set_sample_sum(histogram.sum() as f64);
    h.set_bucket(
        histogram
            .buckets_iter()
            .into_iter()
            .zip(histogram.upper_bounds_iter())
            .map(|(count, upper_bound)| {
                let mut b = Bucket::default();
                b.set_cumulative_count(count);
                b.set_upper_bound(if upper_bound != u64::MAX {
                    upper_bound as f64
                } else {
                    f64::INFINITY
                });
                b
            })
            .collect(),
    );
    m.set_histogram(h);
    m
}
