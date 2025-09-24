/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::query::Filter;
use crate::request::{
    MaybeInvalid,
    deserialize::{DeserializeArguments, deserialize_request},
    reference::{MaybeResultReference, ResultReference},
};
use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use types::id::Id;

#[derive(Debug, Clone)]
pub struct GetSearchSnippetRequest<T> {
    pub account_id: Id,
    pub filter: Vec<Filter<T>>,
    pub email_ids: MaybeResultReference<Vec<MaybeInvalid<Id>>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GetSearchSnippetResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "list")]
    pub list: Vec<SearchSnippet>,

    #[serde(rename = "notFound")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_found: Vec<MaybeInvalid<Id>>,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct SearchSnippet {
    #[serde(rename = "emailId")]
    pub email_id: Id,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

impl<'de, T: DeserializeOwned> DeserializeArguments<'de> for GetSearchSnippetRequest<T> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"filter" => {
                self.filter = map.next_value()?;
            },
            b"emailIds" => {
                self.email_ids = MaybeResultReference::Value(map.next_value::<Vec<MaybeInvalid<Id>>>()?);
            },
            b"#emailIds" => {
                self.email_ids = MaybeResultReference::Reference(map.next_value::<ResultReference>()?);
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for GetSearchSnippetRequest<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T> Default for GetSearchSnippetRequest<T> {
    fn default() -> Self {
        Self {
            account_id: Id::default(),
            filter: Vec::new(),
            email_ids: MaybeResultReference::Value(Vec::new()),
        }
    }
}
