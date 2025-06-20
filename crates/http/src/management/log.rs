/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fs::{self, File},
    io,
    path::Path,
};

use chrono::DateTime;
use common::{Server, auth::AccessToken};
use directory::{Permission, backend::internal::manage};
use rev_lines::RevLines;
use serde::Serialize;
use serde_json::json;
use std::future::Future;
use tokio::sync::oneshot;
use utils::url_params::UrlParams;

use http_proto::*;

#[derive(Serialize)]
struct LogEntry {
    timestamp: String,
    level: String,
    event: String,
    event_id: String,
    details: String,
}

pub trait LogManagement: Sync + Send {
    fn handle_view_logs(
        &self,
        req: &HttpRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl LogManagement for Server {
    async fn handle_view_logs(
        &self,
        req: &HttpRequest,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        // Validate the access token
        access_token.assert_has_permission(Permission::LogsView)?;

        let path = self
            .core
            .metrics
            .log_path
            .clone()
            .ok_or_else(|| manage::unsupported("Tracer log path not configured"))?;

        let params = UrlParams::new(req.uri().query());
        let filter = params.get("filter").unwrap_or_default().to_string();
        let page: usize = params.parse("page").unwrap_or(0);
        let limit: usize = params.parse("limit").unwrap_or(100);
        let offset = page.saturating_sub(1) * limit;

        // TODO: Use worker pool
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(read_log_files(path, &filter, offset, limit));
        });

        let (total, items) = rx
            .await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .caused_by(trc::location!())
            })?
            .map_err(|err| {
                trc::ManageEvent::Error
                    .reason(err)
                    .details("Failed to read log files")
                    .caused_by(trc::location!())
            })?;

        Ok(JsonResponse::new(json!({
            "data": {
                "items": items,
                "total": total,
            },
        }))
        .into_http_response())
    }
}

fn read_log_files(
    path: impl AsRef<Path>,
    filter: &str,
    mut offset: usize,
    limit: usize,
) -> io::Result<(usize, Vec<LogEntry>)> {
    let mut logs = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    let mut total = 0;

    // Sort the entries by file name in reverse order.
    logs.sort_by_key(|b| std::cmp::Reverse(b.file_name()));

    // Iterate and print the file names.
    let mut entries = Vec::with_capacity(limit);
    let mut logs = logs.into_iter();
    while let Some(log) = logs.next() {
        if log.file_type()?.is_file() {
            let mut rev_lines = RevLines::new(File::open(log.path())?);

            while let Some(line) = rev_lines.next() {
                let line = line.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if filter.is_empty() || line.contains(filter) {
                    total += 1;
                    if offset == 0 {
                        if let Some(entry) = LogEntry::from_line(&line) {
                            entries.push(entry);
                            if entries.len() == limit {
                                if rev_lines.next().is_some() || logs.next().is_some() {
                                    total += limit;
                                }

                                return Ok((total, entries));
                            }
                        }
                    } else {
                        offset -= 1;
                    }
                }
            }
        }
    }

    Ok((total, entries))
}

impl LogEntry {
    fn from_line(line: &str) -> Option<Self> {
        let (timestamp, rest) = line.split_once(' ')?;
        let timestamp = DateTime::parse_from_rfc3339(timestamp).ok()?;
        let (level, rest) = rest.trim().split_once(' ')?;
        let (event, rest) = rest.trim().split_once(" (")?;
        let (event_id, details) = rest.split_once(")")?;
        Some(Self {
            timestamp: timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            level: level.to_string(),
            event: event.to_string(),
            event_id: event_id.to_string(),
            details: details.trim().to_string(),
        })
    }
}
