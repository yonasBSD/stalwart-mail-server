/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::HashSet,
    io::{BufRead, BufReader},
    time::{Duration, Instant},
};

use mail_auth::flate2;
use sieve::{runtime::Variable, FunctionMap};
use store::{Deserialize, Value};

use crate::{config::scripts::RemoteList, scripts::into_sieve_value, USER_AGENT};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_exists", plugin_id, 2);
}

pub fn register_get(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_get", plugin_id, 2);
}

pub fn register_set(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_set", plugin_id, 4);
}

pub fn register_remote(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("key_exists_http", plugin_id, 3);
}

pub fn register_local_domain(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("is_local_domain", plugin_id, 2);
}

pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?;

    Ok(match &ctx.arguments[1] {
        Variable::Array(items) => {
            for item in items.iter() {
                if !item.is_empty()
                    && store
                        .key_exists(item.to_string().into_owned().into_bytes())
                        .await?
                {
                    return Ok(true.into());
                }
            }
            false
        }
        v if !v.is_empty() => {
            store
                .key_exists(v.to_string().into_owned().into_bytes())
                .await?
        }
        _ => false,
    }
    .into())
}

pub async fn exec_get(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?
    .key_get::<VariableWrapper>(ctx.arguments[1].to_string().into_owned().into_bytes())
    .await
    .map(|v| v.map(|v| v.into_inner()).unwrap_or_default())
}

pub async fn exec_set(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let expires = match &ctx.arguments[3] {
        Variable::Integer(v) => Some(*v as u64),
        Variable::Float(v) => Some(*v as u64),
        _ => None,
    };

    match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.core.storage.lookups.get(v.as_ref()),
        _ => Some(&ctx.core.storage.lookup),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?
    .key_set(
        ctx.arguments[1].to_string().into_owned().into_bytes(),
        if !ctx.arguments[2].is_empty() {
            bincode::serialize(&ctx.arguments[2]).unwrap_or_default()
        } else {
            vec![]
        },
        expires,
    )
    .await
    .map(|_| true.into())
}

pub async fn exec_remote(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    match exec_remote_(&ctx).await {
        Ok(result) => Ok(result),
        Err(err) => {
            // Something went wrong, try again in one hour
            const RETRY: Duration = Duration::from_secs(3600);

            let mut _lock = ctx.cache.remote_lists.write();
            let list = _lock
                .entry(ctx.arguments[0].to_string().to_string())
                .or_insert_with(|| RemoteList {
                    entries: HashSet::new(),
                    expires: Instant::now(),
                });

            if list.expires > Instant::now() {
                Ok(list
                    .entries
                    .contains(ctx.arguments[1].to_string().as_ref())
                    .into())
            } else {
                list.expires = Instant::now() + RETRY;
                Err(err)
            }
        }
    }
}

async fn exec_remote_(ctx: &PluginContext<'_>) -> trc::Result<Variable> {
    let resource = ctx.arguments[0].to_string();
    let item = ctx.arguments[1].to_string();

    #[cfg(feature = "test_mode")]
    {
        if (resource.contains("open") && item.contains("open"))
            || (resource.contains("tank") && item.contains("tank"))
        {
            return Ok(true.into());
        }
    }

    if resource.is_empty() || item.is_empty() {
        return Ok(false.into());
    }

    const TIMEOUT: Duration = Duration::from_secs(45);
    const MAX_ENTRY_SIZE: usize = 256;
    const MAX_ENTRIES: usize = 100000;

    match ctx.cache.remote_lists.read().get(resource.as_ref()) {
        Some(remote_list) if remote_list.expires < Instant::now() => {
            return Ok(remote_list.entries.contains(item.as_ref()).into())
        }
        _ => {}
    }

    enum Format {
        List,
        Csv {
            column: u32,
            separator: char,
            skip_first: bool,
        },
    }

    // Obtain parameters
    let mut format = Format::List;
    let mut expires = Duration::from_secs(12 * 3600);

    if let Some(arr) = ctx.arguments[2].as_array() {
        // Obtain expiration
        match arr.first() {
            Some(Variable::Integer(v)) if *v > 0 => {
                expires = Duration::from_secs(*v as u64);
            }
            Some(Variable::Float(v)) if *v > 0.0 => {
                expires = Duration::from_secs(*v as u64);
            }
            _ => (),
        }

        // Obtain list type
        if matches!(arr.get(1), Some(Variable::String(list_type)) if list_type.eq_ignore_ascii_case("csv"))
        {
            format = Format::Csv {
                column: arr.get(2).map(|v| v.to_integer()).unwrap_or_default() as u32,
                separator: arr
                    .get(3)
                    .and_then(|v| v.to_string().chars().next())
                    .unwrap_or(','),
                skip_first: arr.get(4).map_or(false, |v| v.to_bool()),
            };
        }
    }

    let response = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
        .unwrap_or_default()
        .get(resource.as_ref())
        .send()
        .await
        .map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .ctx(trc::Key::Url, resource.to_string())
                .details("Failed to build request")
        })?;

    if response.status().is_success() {
        let bytes = response.bytes().await.map_err(|err| {
            trc::SieveEvent::RuntimeError
                .into_err()
                .reason(err)
                .ctx(trc::Key::Url, resource.to_string())
                .details("Failed to fetch resource")
        })?;

        let reader: Box<dyn std::io::Read> = if resource.ends_with(".gz") {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };

        // Lock remote list for writing
        let mut _lock = ctx.cache.remote_lists.write();
        let list = _lock
            .entry(resource.to_string())
            .or_insert_with(|| RemoteList {
                entries: HashSet::new(),
                expires: Instant::now(),
            });

        // Make sure that the list is still expired
        if list.expires > Instant::now() {
            return Ok(list.entries.contains(item.as_ref()).into());
        }

        for (pos, line) in BufReader::new(reader).lines().enumerate() {
            let line_ = line.map_err(|err| {
                trc::SieveEvent::RuntimeError
                    .into_err()
                    .reason(err)
                    .ctx(trc::Key::Url, resource.to_string())
                    .details("Failed to read line")
            })?;
            // Clear list once the first entry has been successfully fetched, decompressed and UTF8-decoded
            if pos == 0 {
                list.entries.clear();
            }

            match &format {
                Format::List => {
                    let line = line_.trim();
                    if !line.is_empty() {
                        list.entries.insert(line.to_string());
                    }
                }
                Format::Csv {
                    column,
                    separator,
                    skip_first,
                } if pos > 0 || !*skip_first => {
                    let mut in_quote = false;
                    let mut col_num = 0;
                    let mut entry = String::new();

                    for ch in line_.chars() {
                        if ch != '"' {
                            if ch == *separator && !in_quote {
                                if col_num == *column {
                                    break;
                                } else {
                                    col_num += 1;
                                }
                            } else if col_num == *column {
                                entry.push(ch);
                                if entry.len() > MAX_ENTRY_SIZE {
                                    break;
                                }
                            }
                        } else {
                            in_quote = !in_quote;
                        }
                    }

                    if !entry.is_empty() {
                        list.entries.insert(entry);
                    }
                }
                _ => (),
            }

            if list.entries.len() == MAX_ENTRIES {
                break;
            }
        }

        trc::event!(
            Spam(trc::SpamEvent::ListUpdated),
            Url = resource.as_ref().to_string(),
            Total = list.entries.len(),
        );

        // Update expiration
        list.expires = Instant::now() + expires;
        return Ok(list.entries.contains(item.as_ref()).into());
    } else {
        trc::bail!(trc::SieveEvent::RuntimeError
            .into_err()
            .ctx(trc::Key::Code, response.status().as_u16())
            .ctx(trc::Key::Url, resource.to_string())
            .details("Failed to fetch remote list"));
    }
}

pub async fn exec_local_domain(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    let domain = ctx.arguments[0].to_string();

    if !domain.is_empty() {
        return match &ctx.arguments[0] {
            Variable::String(v) if !v.is_empty() => ctx.core.storage.directories.get(v.as_ref()),
            _ => Some(&ctx.core.storage.directory),
        }
        .ok_or_else(|| {
            trc::SieveEvent::RuntimeError
                .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
                .details("Unknown directory")
        })?
        .is_local_domain(domain.as_ref())
        .await
        .map(Into::into);
    }

    Ok(Variable::default())
}

#[derive(Debug, PartialEq, Eq)]
pub struct VariableWrapper(Variable);

impl Deserialize for VariableWrapper {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(VariableWrapper(
            bincode::deserialize::<Variable>(bytes).unwrap_or_else(|_| {
                Variable::String(String::from_utf8_lossy(bytes).into_owned().into())
            }),
        ))
    }
}

impl From<i64> for VariableWrapper {
    fn from(value: i64) -> Self {
        VariableWrapper(value.into())
    }
}

impl VariableWrapper {
    pub fn into_inner(self) -> Variable {
        self.0
    }
}

impl From<Value<'static>> for VariableWrapper {
    fn from(value: Value<'static>) -> Self {
        VariableWrapper(into_sieve_value(value))
    }
}
