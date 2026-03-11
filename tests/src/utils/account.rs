/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::jmap::JmapResponse;
use base64::{Engine, engine::general_purpose};
use hyper::header;
use jmap_client::client::{Client, Credentials};
use serde_json::{Value, json};
use std::{fmt::Display, time::Duration};
use types::id::Id;

pub struct Account {
    name: &'static str,
    secret: &'static str,
    emails: &'static [&'static str],
    id: Id,
    id_string: String,
    client: Client,
}

impl Account {
    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn id_string(&self) -> &str {
        &self.id_string
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn secret(&self) -> &'static str {
        self.secret
    }

    pub fn emails(&self) -> &'static [&'static str] {
        self.emails
    }

    pub async fn client_owned(&self) -> Client {
        Client::new()
            .credentials(Credentials::basic(self.name(), self.secret()))
            .timeout(Duration::from_secs(3600))
            .accept_invalid_certs(true)
            .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await
            .unwrap()
    }

    pub async fn jmap_get(
        &self,
        object: impl Display,
        properties: impl IntoIterator<Item = impl Display>,
        ids: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        self.jmap_get_account(self, object, properties, ids).await
    }

    pub async fn jmap_get_account(
        &self,
        account: &Account,
        object: impl Display,
        properties: impl IntoIterator<Item = impl Display>,
        ids: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        let ids = ids
            .into_iter()
            .map(|id| Value::String(id.to_string()))
            .collect::<Vec<Value>>();
        self.jmap_method_calls(json!([[
            format!("{object}/get"),
            {
                "accountId": account.id_string(),
                "properties": properties
                .into_iter()
                .map(|p| Value::String(p.to_string()))
                .collect::<Vec<_>>(),
                "ids": if !ids.is_empty() { Some(ids) } else { None }
            },
            "0"
        ]]))
        .await
    }

    pub async fn jmap_query(
        &self,
        object: impl Display,
        filter: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
        sort_by: impl IntoIterator<Item = impl Display>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let filter = filter
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into()))
            .collect::<serde_json::Map<_, _>>();
        let sort_by = sort_by
            .into_iter()
            .map(|id| {
                json! ({
                    "property": id.to_string()
                })
            })
            .collect::<Vec<Value>>();
        let arguments = [
            ("filter".to_string(), Value::Object(filter)),
            ("sort".to_string(), Value::Array(sort_by)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/query"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_create(
        &self,
        object: impl Display,
        items: impl IntoIterator<Item = Value>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        self.jmap_create_account(self, object, items, arguments)
            .await
    }

    pub async fn jmap_create_account(
        &self,
        account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = Value>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let create = items
            .into_iter()
            .enumerate()
            .map(|(i, item)| (format!("i{i}"), item))
            .collect::<serde_json::Map<_, _>>();
        let arguments = [
            (
                "accountId".to_string(),
                Value::String(account.id_string().to_string()),
            ),
            ("create".to_string(), Value::Object(create)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/set"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_update(
        &self,
        object: impl Display,
        items: impl IntoIterator<Item = (impl Display, Value)>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        self.jmap_update_account(self, object, items, arguments)
            .await
    }

    pub async fn jmap_update_account(
        &self,
        account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = (impl Display, Value)>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let update = items
            .into_iter()
            .map(|(i, item)| (i.to_string(), item))
            .collect::<serde_json::Map<_, _>>();
        let arguments = [
            (
                "accountId".to_string(),
                Value::String(account.id_string().to_string()),
            ),
            ("update".to_string(), Value::Object(update)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/set"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_destroy(
        &self,
        object: impl Display,
        items: impl IntoIterator<Item = impl Display>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        self.jmap_destroy_account(self, object, items, arguments)
            .await
    }

    pub async fn jmap_destroy_account(
        &self,
        account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = impl Display>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let destroy = items
            .into_iter()
            .map(|id| Value::String(id.to_string()))
            .collect::<Vec<_>>();
        let arguments = [
            (
                "accountId".to_string(),
                Value::String(account.id_string().to_string()),
            ),
            ("destroy".to_string(), Value::Array(destroy)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/set"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_copy(
        &self,
        from_account: &Account,
        to_account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = (impl Display, Value)>,
        on_success_destroy: bool,
    ) -> JmapResponse {
        self.jmap_method_calls(json!([[
            format!("{object}/copy"),
            {
                "fromAccountId": from_account.id_string(),
                "accountId": to_account.id_string(),
                "onSuccessDestroyOriginal": on_success_destroy,
                "create": items
                        .into_iter()
                        .map(|(i, item)| (i.to_string(), item)).collect::<serde_json::Map<_, _>>()
            },
            "0"
        ]]))
        .await
    }

    pub async fn jmap_changes(&self, object: impl Display, state: impl Display) -> JmapResponse {
        self.jmap_method_calls(json!([[
            format!("{object}/changes"),
            {
                "sinceState": state.to_string()
            },
            "0"
        ]]))
        .await
    }

    pub async fn jmap_method_call(&self, method_name: &str, body: Value) -> JmapResponse {
        self.jmap_method_calls(json!([[method_name, body, "0"]]))
            .await
    }

    pub async fn jmap_method_calls(&self, calls: Value) -> JmapResponse {
        let mut headers = header::HeaderMap::new();

        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", self.name(), self.secret()))
            ))
            .unwrap(),
        );

        let body = json!({
          "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:quota" ],
          "methodCalls": calls
        });

        JmapResponse(
            serde_json::from_slice(
                &reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .timeout(Duration::from_millis(1000))
                    .default_headers(headers)
                    .build()
                    .unwrap()
                    .post("https://127.0.0.1:8899/jmap")
                    .body(body.to_string())
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap(),
            )
            .unwrap(),
        )
    }

    pub async fn jmap_session_object(&self) -> JmapResponse {
        let mut headers = header::HeaderMap::new();

        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", self.name(), self.secret()))
            ))
            .unwrap(),
        );

        JmapResponse(
            serde_json::from_slice(
                &reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .timeout(Duration::from_millis(1000))
                    .default_headers(headers)
                    .build()
                    .unwrap()
                    .get("https://127.0.0.1:8899/jmap/session")
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap(),
            )
            .unwrap(),
        )
    }

    pub async fn destroy_all_addressbooks(&self) {
        self.jmap_method_calls(json!([[
            "AddressBook/get",
            {
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            "AddressBook/set",
            {
              "#destroy" : {
                    "resultOf": "R1",
                    "name": "AddressBook/get",
                    "path": "/list/*/id"
                },
              "onDestroyRemoveContents" : true
            },
            "R2"
          ]
        ]))
        .await;
    }

    pub async fn destroy_all_calendars(&self) {
        self.jmap_method_calls(json!([[
            "Calendar/get",
            {
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            "Calendar/set",
            {
              "#destroy" : {
                    "resultOf": "R1",
                    "name": "Calendar/get",
                    "path": "/list/*/id"
                },
              "onDestroyRemoveEvents" : true
            },
            "R2"
          ]
        ]))
        .await;
    }

    pub async fn destroy_all_event_notifications(&self) {
        self.jmap_method_calls(json!([[
            "CalendarEventNotification/get",
            {
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            "CalendarEventNotification/set",
            {
              "#destroy" : {
                    "resultOf": "R1",
                    "name": "CalendarEventNotification/get",
                    "path": "/list/*/id"
                }
            },
            "R2"
          ]
        ]))
        .await;
    }
}
