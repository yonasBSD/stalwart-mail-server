/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod telemetry;
// SPDX-SnippetEnd
pub mod diagnose;

use crate::management::diagnose::{DeliveryStage, spawn_delivery_diagnose};
use common::{
    Server,
    auth::{AccessToken, oauth::GrantType},
};
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::{
    HttpRequest, HttpResponse, HttpSessionData, JsonResponse, ToHttpResponse,
    request::{decode_path_element, fetch_body},
};
use hyper::{Method, StatusCode, header};
use jmap::api::{ToJmapHttpResponse, ToRequestError};
use jmap_proto::error::request::RequestError;
use registry::schema::enums::Permission;
use serde_json::json;
use std::time::Duration;
use utils::url_params::UrlParams;

pub trait ManagementApi: Sync + Send {
    fn handle_api_manage_request(
        &self,
        req: &mut HttpRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManagementApi for Server {
    #[allow(unused_variables)]
    async fn handle_api_manage_request(
        &self,
        req: &mut HttpRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        let body = fetch_body(req, 1024 * 1024, session.session_id).await;
        let path = req.uri().path().split('/').skip(2).collect::<Vec<_>>();

        match path.first().copied().unwrap_or_default() {
            "token" => {
                let account_id = access_token.account_id();
                match path.get(1).copied() {
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    Some("tracing") if self.core.is_enterprise_edition() => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::TracingLive)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(JsonResponse::new(json!({
                                "data": self.encode_access_token(GrantType::LiveTracing, account_id,  "web", 60).await?,
                        }))
                        .into_http_response())
                    }
                    #[cfg(feature = "enterprise")]
                    Some("metrics") if self.core.is_enterprise_edition() => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::MetricsLive)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(JsonResponse::new(json!({
                                "data": self.encode_access_token(GrantType::LiveMetrics, account_id,  "web", 60).await?,
                        }))
                        .into_http_response())
                    }
                    // SPDX-SnippetEnd
                    Some("delivery") => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::Troubleshoot)?;

                        // Issue a live telemetry token valid for 60 seconds
                        Ok(JsonResponse::new(json!({
                                "data": self.encode_access_token(GrantType::Diagnose, account_id,  "web", 60).await?,
                        }))
                        .into_http_response())
                    }
                    Some("tracing") | Some("metrics") => {
                        Err(trc::ResourceEvent::NotFound
                            .ctx(trc::Key::Details, "Enterprise feature"))
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }
            "live" => {
                let params = UrlParams::new(req.uri().query());
                let account_id = access_token.account_id();

                match (
                    path.get(1).copied().unwrap_or_default(),
                    path.get(2).copied(),
                    req.method(),
                ) {
                    ("delivery", Some(target), &Method::GET) => {
                        // Validate the access token
                        access_token.enforce_permission(Permission::Troubleshoot)?;

                        let timeout = Duration::from_secs(
                            params
                                .parse::<u64>("timeout")
                                .filter(|interval| *interval >= 1)
                                .unwrap_or(30),
                        );

                        let mut rx = spawn_delivery_diagnose(
                            self.clone(),
                            decode_path_element(target).to_lowercase(),
                            timeout,
                        );

                        Ok(HttpResponse::new(StatusCode::OK)
                            .with_content_type("text/event-stream")
                            .with_cache_control("no-store")
                            .with_stream_body(BoxBody::new(StreamBody::new(
                                async_stream::stream! {
                                    while let Some(stage) = rx.recv().await {
                                        yield Ok(stage.to_frame());
                                    }
                                    yield Ok(DeliveryStage::Completed.to_frame());
                                },
                            ))))
                    }
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    ("traces", _, &Method::GET) if self.core.is_enterprise_edition() => {
                        use crate::management::telemetry::TelemetryApi;

                        self.handle_telemetry_api_request(req, true, access_token)
                            .await
                    }
                    #[cfg(feature = "enterprise")]
                    ("metrics", _, &Method::GET) if self.core.is_enterprise_edition() => {
                        use crate::management::telemetry::TelemetryApi;

                        self.handle_telemetry_api_request(req, false, access_token)
                            .await
                    }
                    // SPDX-SnippetEnd
                    ("traces" | "metrics", _, &Method::GET) => {
                        Err(trc::ResourceEvent::NotFound
                            .ctx(trc::Key::Details, "Enterprise feature"))
                    }
                    _ => Err(trc::ResourceEvent::NotFound.into_err()),
                }
            }

            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

pub trait ToManageHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}

impl ToManageHttpResponse for &trc::Error {
    fn into_http_response(self) -> HttpResponse {
        match self.as_ref() {
            trc::EventType::Auth(
                trc::AuthEvent::Failed | trc::AuthEvent::Error | trc::AuthEvent::TokenExpired,
            ) => HttpResponse::unauthorized(true),
            _ => self.to_request_error().into_http_response(),
        }
    }
}

pub trait UnauthorizedResponse {
    fn unauthorized(include_realms: bool) -> Self;
}

impl UnauthorizedResponse for HttpResponse {
    fn unauthorized(include_realms: bool) -> Self {
        (if include_realms {
            HttpResponse::new(StatusCode::UNAUTHORIZED)
                .with_header(header::WWW_AUTHENTICATE, "Bearer realm=\"Stalwart Server\"")
                .with_header(header::WWW_AUTHENTICATE, "Basic realm=\"Stalwart Server\"")
        } else {
            HttpResponse::new(StatusCode::UNAUTHORIZED)
        })
        .with_content_type("application/problem+json")
        .with_text_body(serde_json::to_string(&RequestError::unauthorized()).unwrap_or_default())
    }
}
