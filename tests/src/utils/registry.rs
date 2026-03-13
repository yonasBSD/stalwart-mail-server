/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{account::Account, jmap::JmapResponse};
use registry::{
    schema::prelude::ObjectType,
    types::{EnumImpl, ObjectImpl},
};
use serde_json::{Value, json};
use std::fmt::Display;
use store::registry::write::RegistryWriteResult;
use types::id::Id;

impl Account {
    pub async fn registry_create<T: ObjectImpl>(
        &self,
        items: impl IntoIterator<Item = T>,
    ) -> JmapResponse {
        let name = T::OBJECT.as_str();

        self.jmap_create_account(
            self,
            format!("x:{name}"),
            items.into_iter().map(|item| {
                let mut item =
                    serde_json::to_value(item).expect("Failed to serialize item to JSON");
                item.as_object_mut()
                    .unwrap()
                    .retain(|k, _| !["createdAt", "credentialId"].contains(&k.as_str()));
                item
            }),
            Vec::<(&str, &str)>::new(),
        )
        .await
    }

    pub async fn registry_update(
        &self,
        object: ObjectType,
        items: impl IntoIterator<Item = (impl Display, Value)>,
    ) -> JmapResponse {
        let name = object.as_str();

        self.jmap_update_account(self, format!("x:{name}"), items, Vec::<(&str, &str)>::new())
            .await
    }

    pub async fn registry_query(
        &self,
        object: ObjectType,
        filter: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
        sort_by: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        let name = object.as_str();

        self.jmap_query(
            format!("x:{name}"),
            filter,
            sort_by,
            Vec::<(&str, &str)>::new(),
        )
        .await
    }

    pub async fn registry_destroy(
        &self,
        object: ObjectType,
        items: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        let name = object.as_str();

        self.jmap_destroy_account(self, format!("x:{name}"), items, Vec::<(&str, &str)>::new())
            .await
    }

    pub async fn registry_destroy_all(&self, object: ObjectType) {
        let name = object.as_str();
        self.jmap_method_calls(json!([[
            format!("{name}/get"),
            {
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            format!("{name}/set"),
            {
              "#destroy" : {
                    "resultOf": "R1",
                    "name": format!("{name}/get"),
                    "path": "/list/*/id"
                },
            },
            "R2"
          ]
        ]))
        .await;
    }

    pub async fn registry_create_object<T: ObjectImpl>(&self, item: T) -> Id {
        self.registry_create([item]).await.created_id(0)
    }
}

impl JmapResponse {
    pub fn objects<T: ObjectImpl>(&self) -> impl Iterator<Item = T> {
        self.list()
            .iter()
            .map(|item| serde_json::from_value(item.clone()).expect("Failed to deserialize item"))
    }
}

pub trait UnwrapRegistryId {
    fn unwrap_id(self, location: &str) -> Id;
}

impl UnwrapRegistryId for RegistryWriteResult {
    fn unwrap_id(self, location: &str) -> Id {
        match self {
            RegistryWriteResult::Success(id) => id,
            err => panic!("Expected success at {location} but got {err}"),
        }
    }
}
