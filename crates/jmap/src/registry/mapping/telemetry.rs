/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse},
        query::RegistryQueryFilters,
    },
};
use common::Server;
use jmap_proto::types::state::State;
use registry::{
    jmap::IntoValue,
    schema::prelude::{Object, Property},
    types::datetime::UTCDateTime,
};
use std::str::FromStr;
use store::{
    IterateParams, ValueKey,
    registry::RegistryFilterOp,
    search::{
        SearchComparator, SearchField, SearchFilter, SearchOperator, SearchQuery,
        TracingSearchField,
    },
    write::{SearchIndex, TelemetryClass, ValueClass, key::DeserializeBigEndian, now},
};
use trc::{AddContext, EventType};
use types::id::Id;
use utils::snowflake::SnowflakeIdGenerator;

pub(crate) async fn trace_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        get.server
            .search_store()
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::gt(
                        SearchField::Id,
                        SnowflakeIdGenerator::from_timestamp(now() - 86400).unwrap_or_default(),
                    ))
                    .with_comparator(SearchComparator::Field {
                        field: SearchField::Id,
                        ascending: false,
                    }),
            )
            .await?
            .into_iter()
            .take(get.server.core.jmap.get_max_objects)
            .map(Id::from)
            .collect()
    };

    for id in ids {
        let item_id = id.id();
        if let Some(trace) = get
            .server
            .tracing_store()
            .get_value::<Object>(ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(
                item_id,
            ))))
            .await?
        {
            get.insert(id, trace.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn metric_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        metric_ids(get.server, get.server.core.jmap.get_max_objects).await?
    };

    for id in ids {
        let item_id = id.id();
        if let Some(metric) = get
            .server
            .metrics_store()
            .get_value::<Object>(ValueKey::from(ValueClass::Telemetry(
                TelemetryClass::Metric(item_id),
            )))
            .await?
        {
            let mut metric = metric.into_value();
            metric.as_object_mut().unwrap().insert_unchecked(
                Property::Timestamp,
                UTCDateTime::from_timestamp(SnowflakeIdGenerator::to_timestamp(item_id) as i64)
                    .into_value(),
            );

            get.insert(id, metric);
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn trace_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut tracing_query = Vec::new();
    tracing_query.push(SearchFilter::And);

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Timestamp => {
                if let Some(id) = value
                    .as_str()
                    .and_then(|s| UTCDateTime::from_str(s).ok())
                    .and_then(|dt| SnowflakeIdGenerator::from_timestamp(dt.timestamp() as u64))
                {
                    let op = match op {
                        RegistryFilterOp::Equal => SearchOperator::Equal,
                        RegistryFilterOp::GreaterThan => SearchOperator::GreaterThan,
                        RegistryFilterOp::GreaterEqualThan => SearchOperator::GreaterEqualThan,
                        RegistryFilterOp::LowerThan => SearchOperator::LowerThan,
                        RegistryFilterOp::LowerEqualThan => SearchOperator::LowerEqualThan,
                        _ => return false,
                    };

                    tracing_query.push(SearchFilter::Operator {
                        field: SearchField::Id,
                        op,
                        value: id.into(),
                    });

                    true
                } else {
                    false
                }
            }
            Property::Event => {
                if let Some(typ) = value.as_str().and_then(EventType::parse) {
                    tracing_query.push(SearchFilter::eq(
                        TracingSearchField::EventType,
                        typ.to_id() as u64,
                    ));
                    true
                } else {
                    false
                }
            }
            Property::QueueId => {
                if let Some(queue_id) = value.as_str().and_then(|s| Id::from_str(s).ok()) {
                    tracing_query
                        .push(SearchFilter::eq(TracingSearchField::QueueId, queue_id.id()));
                    true
                } else {
                    false
                }
            }
            Property::Text => {
                if let Some(query) = value.as_str() {
                    let mut buf = String::with_capacity(query.len());
                    let mut in_quote = false;
                    for ch in query.chars() {
                        if ch.is_ascii_whitespace() {
                            if in_quote {
                                buf.push(' ');
                            } else if !buf.is_empty() {
                                tracing_query.push(SearchFilter::has_keyword(
                                    TracingSearchField::Keywords,
                                    buf,
                                ));
                                buf = String::new();
                            }
                        } else if ch == '"' {
                            buf.push(ch);
                            if in_quote {
                                if !buf.is_empty() {
                                    tracing_query.push(SearchFilter::has_keyword(
                                        TracingSearchField::Keywords,
                                        buf,
                                    ));
                                    buf = String::new();
                                }
                                in_quote = false;
                            } else {
                                in_quote = true;
                            }
                        } else {
                            buf.push(ch);
                        }
                    }
                    if !buf.is_empty() {
                        tracing_query
                            .push(SearchFilter::has_keyword(TracingSearchField::Keywords, buf));
                    }
                    true
                } else {
                    false
                }
            }

            _ => false,
        })?;

    if !tracing_query.iter().any(|f| {
        matches!(
            f,
            SearchFilter::Operator {
                field: SearchField::Tracing(
                    TracingSearchField::Keywords | TracingSearchField::QueueId
                ) | SearchField::Id,
                ..
            }
        )
    }) {
        tracing_query.push(SearchFilter::gt(
            SearchField::Id,
            SnowflakeIdGenerator::from_timestamp(now() - 86400).unwrap_or_default(),
        ));
    }
    tracing_query.push(SearchFilter::End);

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;

    if !matches!(params.sort_by, Property::Id | Property::Timestamp) {
        return Err(trc::JmapEvent::UnsupportedSort.into_err().details(format!(
            "Property {} is not supported for sorting",
            params.sort_by
        )));
    }

    let results = req
        .server
        .search_store()
        .query_global(
            SearchQuery::new(SearchIndex::Tracing)
                .with_filters(tracing_query)
                .with_comparator(SearchComparator::Field {
                    field: SearchField::Id,
                    ascending: params.sort_ascending,
                }),
        )
        .await?;

    // Build response
    let mut response = QueryResponseBuilder::new(
        results.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    for id in results {
        if !response.add_id(id.into()) {
            break;
        }
    }

    Ok(response)
}

pub(crate) async fn metric_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut ts_from = 0u64;
    let mut ts_to = u64::MAX;

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Timestamp => {
                if let Some(ts) = value.as_str().and_then(|s| UTCDateTime::from_str(s).ok()) {
                    let ts = ts.timestamp() as u64;
                    let (from, to) = match op {
                        RegistryFilterOp::Equal => (ts, ts),
                        RegistryFilterOp::GreaterThan => (ts + 1, u64::MAX),
                        RegistryFilterOp::GreaterEqualThan => (ts, u64::MAX),
                        RegistryFilterOp::LowerThan => (0, ts - 1),
                        RegistryFilterOp::LowerEqualThan => (0, ts),
                        _ => return false,
                    };

                    // Intersect with existing range
                    ts_from = ts_from.max(from);
                    ts_to = ts_to.min(to);

                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;

    if ts_from != 0 {
        ts_from = SnowflakeIdGenerator::from_timestamp(ts_from).unwrap_or(0);
    }

    if ts_to != u64::MAX {
        ts_to = SnowflakeIdGenerator::from_timestamp(ts_to).unwrap_or(u64::MAX);
    }

    let from_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(ts_from)));
    let to_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(ts_to)));

    // Build response
    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    if response.response.total.is_some() {
        response.response.total = Some(0);
    }

    req.server
        .metrics_store()
        .iterate(
            IterateParams::new(from_key, to_key)
                .set_ascending(params.sort_ascending)
                .no_values(),
            |key, _| {
                let id = key.deserialize_be_u64(0)?;
                if let Some(total) = response.response.total.as_mut() {
                    *total += 1;
                    if !response.is_full() {
                        response.add_id(id.into());
                    }
                    Ok(true)
                } else {
                    Ok(response.add_id(id.into()))
                }
            },
        )
        .await
        .caused_by(trc::location!())?;

    if let (Some(total), Some(limit)) = (response.response.total, response.response.limit)
        && total < limit
    {
        response.response.limit = None;
    }

    Ok(response)
}

async fn metric_ids(server: &Server, max_results: usize) -> trc::Result<Vec<Id>> {
    let mut events = Vec::with_capacity(8);

    let from_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(0)));
    let to_key = ValueKey::from(ValueClass::Telemetry(TelemetryClass::Metric(u64::MAX)));

    server
        .metrics_store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                events.push(key.deserialize_be_u64(0)?.into());

                Ok(events.len() < max_results)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| events)
}
