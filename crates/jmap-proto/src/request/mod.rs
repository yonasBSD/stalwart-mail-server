/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod capability;
pub mod method;
pub mod parser;
pub mod reference;
pub mod websocket;

use jmap_tools::{Null, Value};

use self::method::MethodName;
use crate::method::{
    changes::ChangesRequest,
    copy::{self, CopyBlobRequest, CopyRequest},
    get::{self, GetRequest},
    import::ImportEmailRequest,
    lookup::BlobLookupRequest,
    parse::ParseEmailRequest,
    query::{self, QueryRequest},
    query_changes::QueryChangesRequest,
    search_snippet::GetSearchSnippetRequest,
    set::{self, SetRequest},
    upload::BlobUploadRequest,
    validate::ValidateSieveScriptRequest,
};
use std::{collections::HashMap, fmt::Debug};

#[derive(Debug, Default)]
pub struct Request<'x> {
    pub using: u32,
    pub method_calls: Vec<Call<RequestMethod<'x>>>,
    pub created_ids: Option<HashMap<String, String>>,
}

#[derive(Debug)]
pub struct Call<T> {
    pub id: String,
    pub name: MethodName,
    pub method: T,
}

#[derive(Debug)]
pub enum RequestMethod<'x> {
    //Get(GetRequest<get::RequestArguments>),
    //Set(SetRequest<set::RequestArguments>),
    Changes(ChangesRequest),
    //Copy(CopyRequest<copy::RequestArguments>),
    CopyBlob(CopyBlobRequest),
    ImportEmail(ImportEmailRequest),
    ParseEmail(ParseEmailRequest),
    //QueryChanges(QueryChangesRequest),
    //Query(QueryRequest<query::RequestArguments>),
    SearchSnippet(GetSearchSnippetRequest),
    ValidateScript(ValidateSieveScriptRequest),
    LookupBlob(BlobLookupRequest),
    UploadBlob(BlobUploadRequest),
    Echo(Value<'x, Null, Null>),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeInvalid<V> {
    Id(V),
    Invalid(String),
}
