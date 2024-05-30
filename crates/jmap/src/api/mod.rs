/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use hyper::StatusCode;
use jmap_proto::types::{id::Id, state::State, type_state::DataType};
use serde::Serialize;
use utils::map::vec_map::VecMap;

use crate::JmapInstance;

pub mod autoconfig;
pub mod event_source;
pub mod http;
pub mod management;
pub mod request;
pub mod session;

#[derive(Clone)]
pub struct JmapSessionManager {
    pub inner: JmapInstance,
}

impl JmapSessionManager {
    pub fn new(inner: JmapInstance) -> Self {
        Self { inner }
    }
}

pub struct JsonResponse<T: Serialize> {
    status: StatusCode,
    inner: T,
}

pub struct HtmlResponse {
    status: StatusCode,
    body: String,
}

pub type HttpRequest = hyper::Request<hyper::body::Incoming>;
pub type HttpResponse =
    hyper::Response<http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>>;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum StateChangeType {
    StateChange,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct StateChangeResponse {
    #[serde(rename = "@type")]
    pub type_: StateChangeType,
    pub changed: VecMap<Id, VecMap<DataType, State>>,
}

impl StateChangeResponse {
    pub fn new() -> Self {
        Self {
            type_: StateChangeType::StateChange,
            changed: VecMap::new(),
        }
    }
}

impl Default for StateChangeResponse {
    fn default() -> Self {
        Self::new()
    }
}
