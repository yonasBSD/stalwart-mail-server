/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::JmapObject,
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
        reference::{MaybeIdReference, MaybeResultReference, ResultReference},
    },
    types::state::State,
};
use jmap_tools::{Property, Value};
use serde::{Deserialize, Deserializer};
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone)]
pub struct GetRequest<T: JmapObject> {
    pub account_id: Id,
    pub ids: Option<MaybeResultReference<Vec<MaybeIdReference<T::Id>>>>,
    pub properties: Option<MaybeResultReference<Vec<MaybeInvalid<T::Property>>>>,
    pub arguments: T::GetArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GetResponse<T: JmapObject> {
    #[serde(rename = "accountId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<Id>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,

    pub list: Vec<Value<'static, T::Property, T::Element>>,

    #[serde(rename = "notFound")]
    pub not_found: Vec<MaybeInvalid<T::Id>>,
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for GetRequest<T> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"ids" => {
                self.ids = map.next_value::<Option<Vec<MaybeIdReference<T::Id>>>>()?.map(MaybeResultReference::Value);
            },
            b"properties" => {
                self.properties = map.next_value::<Option<Vec<MaybeInvalid<T::Property>>>>()?.map(MaybeResultReference::Value);
            },
            b"#ids" => {
                self.ids = Some(MaybeResultReference::Reference(map.next_value::<ResultReference>()?));
            },
            b"#properties" => {
                self.properties = Some(MaybeResultReference::Reference(map.next_value::<ResultReference>()?));
            },
            _ => {
                self.arguments.deserialize_argument(key, map)?;
            }
        );

        Ok(())
    }
}

impl<'de, T: JmapObject> Deserialize<'de> for GetRequest<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T: JmapObject> Default for GetRequest<T> {
    fn default() -> Self {
        Self {
            account_id: Id::default(),
            ids: None,
            properties: None,
            arguments: T::GetArguments::default(),
        }
    }
}

/*
impl<T: JmapObject> GetRequest<T> {
    pub fn unwrap_properties(&mut self, default: &[T::Property]) -> Vec<T::Property> {
        if let Some(mut properties) = self.properties.take().map(|p| p.unwrap()) {
            // Add Id Property
            if !properties.contains(&Property::Id) {
                properties.push(Property::Id);
            }
            properties
        } else {
            default.to_vec()
        }
    }

    pub fn unwrap_ids(&mut self, max_objects_in_get: usize) -> trc::Result<Option<Vec<T::Id>>> {
        if let Some(ids) = self.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= max_objects_in_get {
                Ok(Some(
                    ids.into_iter()
                        .filter_map(|id| id.try_unwrap().and_then(|id| id.into_id()))
                        .collect::<Vec<_>>(),
                ))
            } else {
                Err(trc::JmapEvent::RequestTooLarge.into_err())
            }
        } else {
            Ok(None)
        }
    }

    pub fn unwrap_blob_ids(
        &mut self,
        max_objects_in_get: usize,
    ) -> trc::Result<Option<Vec<BlobId>>> {
        if let Some(ids) = self.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= max_objects_in_get {
                Ok(Some(
                    ids.into_iter()
                        .filter_map(|id| id.try_unwrap().and_then(|id| id.into_blob_id()))
                        .collect::<Vec<_>>(),
                ))
            } else {
                Err(trc::JmapEvent::RequestTooLarge.into_err())
            }
        } else {
            Ok(None)
        }
    }
}
*/
