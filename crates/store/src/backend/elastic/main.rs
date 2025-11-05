/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::backend::elastic::ElasticSearchStore;
use reqwest::Client;
use serde_json::json;
use utils::config::{Config, http::build_http_client, utils::AsKey};

pub(crate) static INDEX_NAMES: &[&str] = &["stalwart_email"];

impl ElasticSearchStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let client = build_http_client(config, prefix.clone())?;
        let url = config
            .value_require((&prefix, "url"))?
            .trim_end_matches("/");
        Url::parse(url)
            .map_err(|e| config.new_parse_error((&prefix, "url"), format!("Invalid URL: {e}",)))
            .ok()?;
        let es = Self {
            client,
            url: url.to_string(),
        };

        if let Err(err) = es
            .create_index(
                config
                    .property_or_default((&prefix, "index.shards"), "3")
                    .unwrap_or(3),
                config
                    .property_or_default((&prefix, "index.replicas"), "0")
                    .unwrap_or(0),
            )
            .await
        {
            config.new_build_error(prefix.as_str(), err.to_string());
        }

        Some(es)
    }

    async fn create_index(&self, shards: usize, replicas: usize) -> trc::Result<()> {
        let exists = self
            .index
            .indices()
            .exists(IndicesExistsParts::Index(&[INDEX_NAMES[0]]))
            .send()
            .await
            .map_err(|err| trc::StoreEvent::ElasticsearchError.reason(err))?;

        if exists.status_code() == StatusCode::NOT_FOUND {
            let response = self
                .index
                .indices()
                .create(IndicesCreateParts::Index(INDEX_NAMES[0]))
                .body(json!({
                  "mappings": {
                    "properties": {
                      "document_id": {
                        "type": "integer"
                      },
                      "account_id": {
                        "type": "integer"
                      },
                      "header": {
                        "type": "object",
                        "properties": {
                          "name": {
                            "type": "keyword"
                          },
                          "value": {
                            "type": "text",
                            "analyzer": "default_analyzer",
                          }
                        }
                      },
                      "body": {
                        "analyzer": "default_analyzer",
                        "type": "text"
                      },
                      "attachment": {
                        "analyzer": "default_analyzer",
                        "type": "text"
                      },
                      "keyword": {
                        "type": "keyword"
                      }
                    }
                  },
                  "settings": {
                    "index.number_of_shards": shards,
                    "index.number_of_replicas": replicas,
                    "analysis": {
                      "analyzer": {
                        "default_analyzer": {
                          "type": "custom",
                          "tokenizer": "standard",
                          "filter": ["lowercase"]
                        }
                      }
                    }
                  }
                }))
                .send()
                .await;

            assert_success(response).await?;
        }

        Ok(())
    }
}

/*pub(crate) async fn assert_success(response: Result<Response, Error>) -> trc::Result<Response> {
    match response {
        Ok(response) => {
            let status = response.status_code();
            if status.is_success() {
                Ok(response)
            } else {
                Err(trc::StoreEvent::ElasticsearchError
                    .reason(response.text().await.unwrap_or_default())
                    .ctx(trc::Key::Code, status.as_u16()))
            }
        }
        Err(err) => Err(trc::StoreEvent::ElasticsearchError.reason(err)),
    }
}
*/
