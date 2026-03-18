/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapSetError},
};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::Action,
    },
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
                remove_server_set_props(&mut item);
                item
            }),
            Vec::<(&str, &str)>::new(),
        )
        .await
    }

    pub async fn registry_get<T: ObjectImpl>(&self, id: Id) -> T {
        let name = T::OBJECT.as_str();

        let value = self
            .jmap_get_account(self, format!("x:{name}"), Vec::<&str>::new(), vec![id])
            .await
            .list()[0]
            .to_string();
        serde_json::from_str(&value).expect("Failed to deserialize item")
    }

    pub async fn registry_get_many(
        &self,
        object_type: ObjectType,
        ids: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        self.jmap_get_account(
            self,
            format!("x:{}", object_type.as_str()),
            Vec::<&str>::new(),
            ids,
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

    pub async fn registry_query_ids(
        &self,
        object: ObjectType,
        filter: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
        sort_by: impl IntoIterator<Item = impl Display>,
    ) -> Vec<Id> {
        self.registry_query(object, filter, sort_by)
            .await
            .object_ids()
            .collect()
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
            format!("x:{name}/get"),
            {
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            format!("x:{name}/set"),
            {
              "#destroy" : {
                    "resultOf": "R1",
                    "name": format!("x:{name}/get"),
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

    pub async fn registry_create_object_expect_err<T: ObjectImpl>(&self, item: T) -> JmapSetError {
        let v = self
            .registry_create([item])
            .await
            .not_created(0)
            .to_string();
        serde_json::from_str(&v).expect("Failed to deserialize set error")
    }

    pub async fn registry_update_object(&self, object: ObjectType, id: Id, item: Value) {
        self.registry_update(object, [(id, item)])
            .await
            .updated_id(id);
    }

    pub async fn registry_update_setting<T: ObjectImpl>(
        &self,
        setting: T,
        properties: &[Property],
    ) {
        let mut item = serde_json::to_value(setting).expect("Failed to serialize setting to JSON");

        if !properties.is_empty() {
            // Only include the specified properties in the update
            if let Value::Object(obj) = &mut item {
                obj.retain(|k, _| properties.iter().any(|p| p.as_str() == k));
            }
        }

        self.registry_update(T::OBJECT, [(Id::singleton(), item)])
            .await
            .updated_id(Id::singleton());
    }

    pub async fn reload_settings(&self) {
        self.registry_create_object(Action::ReloadSettings).await;
    }

    pub async fn registry_update_object_expect_err(
        &self,
        object: ObjectType,
        id: Id,
        item: Value,
    ) -> JmapSetError {
        let v = self
            .registry_update(object, [(id, item)])
            .await
            .not_updated(&id.to_string())
            .to_string();
        serde_json::from_str(&v).expect("Failed to deserialize set error")
    }

    pub async fn registry_destroy_object_expect_err(
        &self,
        object: ObjectType,
        id: Id,
    ) -> JmapSetError {
        let v = self
            .registry_destroy(object, [id])
            .await
            .not_destroyed(&id.to_string())
            .to_string();
        serde_json::from_str(&v).expect("Failed to deserialize set error")
    }

    pub async fn destroy_account(&self, account: Account) {
        let account_id = account.id();
        self.registry_destroy(ObjectType::Account, [account_id])
            .await
            .assert_destroyed(&[account_id]);
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

fn remove_server_set_props(value: &mut serde_json::Value) {
    if let Value::Object(obj) = value {
        let is_app_pass = obj
            .get("@type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| ["AppPassword", "ApiKey"].contains(&t));
        obj.retain(|k, v| {
            !(["createdAt", "credentialId", "retireAt"].contains(&k.as_str())
                || (is_app_pass && k == "secret")
                || (k == "memberTenantId" && v.is_null()))
        });
        for v in obj.values_mut() {
            remove_server_set_props(v);
        }
    }
}
