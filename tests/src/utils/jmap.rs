/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde_json::Value;
use std::fmt::Display;

pub struct JmapResponse(pub Value);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChangeType<'x> {
    Created(&'x str),
    Updated(&'x str),
    Destroyed(&'x str),
}

impl JmapResponse {
    pub fn created(&self, item_idx: u32) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/created/i{item_idx}"))
            .unwrap_or_else(|| panic!("Missing created item {item_idx}: {self:?}"))
    }

    pub fn not_created(&self, item_idx: u32) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/notCreated/i{item_idx}"))
            .unwrap_or_else(|| panic!("Missing not created item {item_idx}: {self:?}"))
    }

    pub fn updated(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/updated/{id}"))
            .unwrap_or_else(|| panic!("Missing updated item {id}: {self:?}"))
    }

    pub fn not_updated(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/notUpdated/{id}"))
            .unwrap_or_else(|| panic!("Missing not updated item {id}: {self:?}"))
    }

    pub fn copied(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/created/{id}"))
            .unwrap_or_else(|| panic!("Missing created item {id}: {self:?}"))
    }

    pub fn method_response(&self) -> &Value {
        self.0
            .pointer("/methodResponses/0/1")
            .unwrap_or_else(|| panic!("Missing method response in response: {self:?}"))
    }

    pub fn list_array(&self) -> &Value {
        self.0
            .pointer("/methodResponses/0/1/list")
            .unwrap_or_else(|| panic!("Missing list in response: {self:?}"))
    }

    pub fn list(&self) -> &[Value] {
        self.0
            .pointer("/methodResponses/0/1/list")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing list in response: {self:?}"))
    }

    pub fn not_found(&self) -> impl Iterator<Item = &str> {
        self.0
            .pointer("/methodResponses/0/1/notFound")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing notFound in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.0
            .pointer("/methodResponses/0/1/ids")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing ids in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn destroyed(&self) -> impl Iterator<Item = &str> {
        self.0
            .pointer("/methodResponses/0/1/destroyed")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing destroyed in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn not_destroyed(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/notDestroyed/{id}"))
            .unwrap_or_else(|| panic!("Missing not destroyed item {id}: {self:?}"))
    }

    pub fn state(&self) -> &str {
        self.0
            .pointer("/methodResponses/0/1/state")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing state in response: {self:?}"))
    }

    pub fn new_state(&self) -> &str {
        self.0
            .pointer("/methodResponses/0/1/newState")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing new state in response: {self:?}"))
    }

    pub fn changes(&self) -> impl Iterator<Item = ChangeType<'_>> {
        self.changes_by_type("created")
            .map(ChangeType::Created)
            .chain(self.changes_by_type("updated").map(ChangeType::Updated))
            .chain(self.changes_by_type("destroyed").map(ChangeType::Destroyed))
    }

    fn changes_by_type(&self, typ: &str) -> impl Iterator<Item = &str> {
        self.0
            .pointer(&format!("/methodResponses/0/1/{typ}"))
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing {typ} changes in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn pointer(&self, pointer: &str) -> Option<&Value> {
        self.0.pointer(pointer)
    }

    pub fn into_inner(self) -> Value {
        self.0
    }
}

pub trait JmapUtils {
    fn id(&self) -> &str {
        self.text_field("id")
    }

    fn blob_id(&self) -> &str {
        self.text_field("blobId")
    }

    fn typ(&self) -> &str {
        self.text_field("type")
    }

    fn description(&self) -> &str {
        self.text_field("description")
    }

    fn with_property(self, field: impl Display, value: impl Into<Value>) -> Self;

    fn text_field(&self, field: &str) -> &str;

    fn assert_is_equal(&self, other: Value);
}

impl JmapUtils for Value {
    fn text_field(&self, field: &str) -> &str {
        self.pointer(&format!("/{field}"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing {field} in object: {self:?}"))
    }
    fn assert_is_equal(&self, expected: Value) {
        if self != &expected {
            panic!(
                "Values are not equal:\ngot: {}\nexpected: {}",
                serde_json::to_string_pretty(self).unwrap(),
                serde_json::to_string_pretty(&expected).unwrap()
            );
        }
    }
    fn with_property(mut self, field: impl Display, value: impl Into<Value>) -> Self {
        if let Value::Object(map) = &mut self {
            map.insert(field.to_string(), value.into());
        } else {
            panic!("Not an object: {self:?}");
        }
        self
    }
}

impl<'x> ChangeType<'x> {
    pub fn as_created(&self) -> &str {
        match self {
            ChangeType::Created(id) => id,
            _ => panic!("Not a created change: {self:?}"),
        }
    }

    pub fn as_updated(&self) -> &str {
        match self {
            ChangeType::Updated(id) => id,
            _ => panic!("Not an updated change: {self:?}"),
        }
    }

    pub fn as_destroyed(&self) -> &str {
        match self {
            ChangeType::Destroyed(id) => id,
            _ => panic!("Not a destroyed change: {self:?}"),
        }
    }
}

impl Display for JmapResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::fmt::Debug for JmapResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        serde_json::to_string_pretty(&self.0)
            .map_err(|_| std::fmt::Error)
            .and_then(|s| std::fmt::Display::fmt(&s, f))
    }
}

pub trait IntoJmapSet {
    fn into_jmap_set(self) -> Value;
}

impl<T: IntoIterator<Item = impl Display>> IntoJmapSet for T {
    fn into_jmap_set(self) -> Value {
        Value::Object(
            self.into_iter()
                .map(|id| (id.to_string(), Value::Bool(true)))
                .collect::<serde_json::Map<String, Value>>(),
        )
    }
}
