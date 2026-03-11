/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{
            RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse,
            principal::build_set_error,
        },
        query::RegistryQueryFilters,
        set::map_write_error,
    },
};
use common::{
    auth::{
        AccessToken, Permissions, PermissionsGroup,
        credential::{ApiKey, AppPassword},
        permissions::BuildPermissions,
    },
    cache::invalidate::CacheInvalidationBuilder,
    ipc::CacheInvalidation,
};
use directory::core::secret::{hash_secret, verify_otp_auth, verify_secret_hash};
use jmap_proto::{error::set::SetError, types::state::State};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, MaybeUnpatched, RegistryJsonPatch, RegistryValue},
    schema::{
        enums::{CredentialType, StorageQuota},
        prelude::{MASKED_PASSWORD, Object, ObjectInner, ObjectType, Property},
        structs::{
            Account, AccountSettings, Credential, CredentialPermissions, SecondaryCredential,
        },
    },
    types::{EnumImpl, datetime::UTCDateTime, id::ObjectId},
};
use std::str::FromStr;
use store::registry::{
    RegistryFilterOp,
    write::{RegistryWrite, RegistryWriteResult},
};
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub(crate) async fn account_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    let item_id = Id::from(set.account_id);
    let Some(object) = set
        .server
        .registry()
        .get(ObjectId::new(ObjectType::Account, item_id))
        .await?
    else {
        set.fail_all(SetError::not_found());
        return Ok(set);
    };
    let revision = object.revision;
    let old_account = if let ObjectInner::Account(Account::User(account)) = object.inner {
        account
    } else {
        set.fail_all(SetError::not_found());
        return Ok(set);
    };
    let mut account = old_account.clone();

    match set.object_type {
        ObjectType::AccountSettings => {
            'outer: for (id, value) in set.update.drain(..) {
                if id != Id::singleton() {
                    set.response.not_updated.append(id, SetError::not_found());
                }

                for (key, value) in value.into_expanded_object() {
                    if let Key::Property(
                        property @ (Property::EncryptionAtRest
                        | Property::Locale
                        | Property::Description),
                    ) = key
                    {
                        let ptr =
                            JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(property))]);
                        if let Err(err) =
                            account.patch(JsonPointerPatch::new(&ptr).with_create(false), value)
                        {
                            set.response.not_updated.append(id, err.into());
                            break 'outer;
                        }
                    } else {
                        set.response.not_updated.append(
                            id,
                            SetError::invalid_properties().with_property(key.into_owned()),
                        );
                        break 'outer;
                    }
                }
            }
        }
        ObjectType::Credential => {
            // Process creations
            if !set.create.is_empty() {
                let account_cache = set.server.account(set.account_id).await?;
                let app_pass_quota = set
                    .server
                    .object_quota(account_cache.object_quotas(), StorageQuota::MaxAppPasswords);
                let api_key_quota = set
                    .server
                    .object_quota(account_cache.object_quotas(), StorageQuota::MaxApiKeys);
                let mut last_credential_id = 0;
                let mut app_pass_total = 0;
                let mut api_key_total = 0;

                for credential in account.credentials.values() {
                    match credential {
                        Credential::Password(c) => {
                            let credential_id = c.credential_id.id();
                            if credential_id > last_credential_id {
                                last_credential_id = credential_id;
                            }
                        }
                        Credential::AppPassword(c) => {
                            let credential_id = c.credential_id.id();
                            if credential_id > last_credential_id {
                                last_credential_id = credential_id;
                            }
                            app_pass_total += 1;
                        }
                        Credential::ApiKey(c) => {
                            let credential_id = c.credential_id.id();
                            if credential_id > last_credential_id {
                                last_credential_id = credential_id;
                            }
                            api_key_total += 1;
                        }
                    }
                }

                'outer: for (id, value) in set.create.drain() {
                    let mut credential = Credential::default();

                    for (key, value) in value.into_expanded_object() {
                        let Key::Property(prop) = key else {
                            set.response.not_created.append(
                                id,
                                SetError::invalid_properties().with_property(key.into_owned()),
                            );
                            continue 'outer;
                        };
                        let ptr = JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))]);

                        // Patch object
                        match credential.patch(JsonPointerPatch::new(&ptr).with_create(true), value)
                        {
                            Ok(MaybeUnpatched::Patched) => {}
                            Ok(
                                MaybeUnpatched::Unpatched { .. }
                                | MaybeUnpatched::UnpatchedMany { .. },
                            ) => {
                                set.response.not_created.append(
                                    id,
                                    SetError::invalid_properties()
                                        .with_property(prop)
                                        .with_description("Cannot set property during creation."),
                                );
                                continue 'outer;
                            }
                            Err(err) => {
                                set.response.not_created.append(id, err.into());
                                continue 'outer;
                            }
                        }
                    }

                    // Validate credential
                    match &mut credential {
                        Credential::AppPassword(credential) => {
                            if app_pass_total >= app_pass_quota {
                                set.response.not_created.append(
                                    id,
                                    SetError::over_quota().with_description(format!(
                                        "You have exceeded your quota of {} app passwords.",
                                        app_pass_quota
                                    )),
                                );
                                continue 'outer;
                            }
                            if let Err(err) =
                                validate_credential_permissions(set.access_token, credential)
                            {
                                set.response.not_created.append(id, err);
                                continue 'outer;
                            }

                            // Assign id
                            last_credential_id += 1;
                            app_pass_total += 1;
                            credential.credential_id = last_credential_id.into();

                            // Generate App password and hash secret
                            let app_ass = AppPassword::new(last_credential_id as u32).build();
                            credential.secret = hash_secret(
                                set.server.core.network.security.password_hash_algorithm,
                                app_ass.clone(),
                            )
                            .await
                            .caused_by(trc::location!())?;
                            set.response.created.insert(
                                id,
                                Value::Object(Map::from(vec![
                                    (
                                        Key::Property(Property::Secret),
                                        Value::Element(RegistryValue::Id(
                                            last_credential_id.into(),
                                        )),
                                    ),
                                    (Key::Property(Property::Secret), Value::Str(app_ass.into())),
                                ])),
                            );
                        }
                        Credential::ApiKey(credential) => {
                            if api_key_total >= api_key_quota {
                                set.response.not_created.append(
                                    id,
                                    SetError::over_quota().with_description(format!(
                                        "You have exceeded your quota of {} API keys.",
                                        api_key_quota
                                    )),
                                );
                                continue 'outer;
                            }
                            if let Err(err) =
                                validate_credential_permissions(set.access_token, credential)
                            {
                                set.response.not_created.append(id, err);
                                continue 'outer;
                            }

                            // Assign id
                            last_credential_id += 1;
                            api_key_total += 1;
                            credential.credential_id = last_credential_id.into();

                            // Generate API key and hash secret
                            let api_key =
                                ApiKey::new(set.account_id, last_credential_id as u32).build();
                            credential.secret = hash_secret(
                                set.server.core.network.security.password_hash_algorithm,
                                api_key.clone(),
                            )
                            .await
                            .caused_by(trc::location!())?;
                            set.response.created.insert(
                                id,
                                Value::Object(Map::from(vec![
                                    (
                                        Key::Property(Property::Secret),
                                        Value::Element(RegistryValue::Id(
                                            last_credential_id.into(),
                                        )),
                                    ),
                                    (Key::Property(Property::Secret), Value::Str(api_key.into())),
                                ])),
                            );
                        }
                        Credential::Password(_) => {
                            set.response.not_created.append(
                                id,
                                SetError::forbidden()
                                    .with_description("Cannot create a password credential."),
                            );
                        }
                    }
                }
            }

            // Process updates
            'outer: for (id, value) in set.update.drain(..) {
                if let Some(credential) = account
                    .credentials
                    .values_mut()
                    .find(|credential| credential.credential_id() == id)
                {
                    let old_credential = credential.clone();
                    let mut unpatched_properties = VecMap::new();

                    for (key, value) in value.into_expanded_object() {
                        let ptr = match key {
                            Key::Property(prop) => {
                                JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                            }
                            Key::Borrowed(other) => JsonPointer::parse(other),
                            Key::Owned(other) => JsonPointer::parse(&other),
                        };

                        match credential
                            .patch(JsonPointerPatch::new(&ptr).with_create(false), value)
                        {
                            Ok(MaybeUnpatched::Patched) => {}
                            Ok(MaybeUnpatched::Unpatched { property, value }) => {
                                unpatched_properties.append(property, value);
                            }
                            Ok(MaybeUnpatched::UnpatchedMany { properties }) => {
                                if unpatched_properties.is_empty() {
                                    unpatched_properties = properties;
                                } else {
                                    unpatched_properties.extend(properties);
                                }
                            }
                            Err(err) => {
                                set.response.not_updated.append(id, err.into());
                                continue 'outer;
                            }
                        }
                    }

                    if credential == &old_credential {
                        set.response.updated.append(id, None);
                        continue 'outer;
                    }

                    match (credential, old_credential) {
                        (
                            Credential::Password(credential),
                            Credential::Password(old_credential),
                        ) => {
                            // Reset the original password if the client accidentally sent the masked password
                            if credential.secret.is_empty() || credential.secret == MASKED_PASSWORD
                            {
                                credential.secret = old_credential.secret.clone();
                            }
                            if credential
                                .otp_auth
                                .as_ref()
                                .is_some_and(|otp_auth| otp_auth == MASKED_PASSWORD)
                            {
                                credential.otp_auth = old_credential.otp_auth.clone();
                            }

                            // Users cannot modify their allowedIps or expiration
                            if credential.allowed_ips != old_credential.allowed_ips
                                || credential.expires_at != old_credential.expires_at
                            {
                                set.response.not_updated.append(
                                    id,
                                    SetError::forbidden().with_description(
                                        "Modifying allowed IPs or expiration is not allowed.",
                                    ),
                                );
                                continue 'outer;
                            }

                            // Password changes are not supported when using external directories
                            if (credential.secret != old_credential.secret
                                || credential.otp_auth != old_credential.otp_auth)
                                && set
                                    .server
                                    .domain_by_id(account.domain_id.document_id())
                                    .await?
                                    .and_then(|domain| domain.id_directory)
                                    .and_then(|domain_id| set.server.get_directory(&domain_id))
                                    .or_else(|| set.server.get_default_directory())
                                    .is_some()
                            {
                                set.response.not_updated.append(
                                    id,
                                    SetError::forbidden()
                                        .with_description("Operation not allowed."),
                                );
                                continue 'outer;
                            }

                            if credential.secret != old_credential.secret
                                || credential.otp_auth != old_credential.otp_auth
                            {
                                if old_credential.secret.is_empty() {
                                    set.response.not_updated.append(
                                        id,
                                        SetError::forbidden().with_description(
                                            "Cannot set a password or OTP auth on an account that doesn't have one.",
                                        ),
                                    );
                                    continue 'outer;
                                }

                                let current_otp_code = unpatched_properties
                                    .get(&Property::OtpCode)
                                    .and_then(|v| v.as_str())
                                    .filter(|v| !v.is_empty());
                                if let Some(current_secret) = unpatched_properties
                                    .get(&Property::CurrentSecret)
                                    .and_then(|v| v.as_str())
                                    .filter(|v| !v.is_empty())
                                {
                                    if !verify_secret_hash(
                                        &old_credential.secret,
                                        current_secret.as_bytes(),
                                    )
                                    .await?
                                        || !verify_otp_auth(
                                            old_credential.otp_auth.as_deref(),
                                            current_otp_code.as_deref(),
                                        )?
                                    {
                                        let account = set.server.account(set.account_id).await?;
                                        if set.server.has_auth_fail2ban()
                                            && set
                                                .server
                                                .is_auth_fail2banned(
                                                    set.remote_ip,
                                                    account.name().into(),
                                                )
                                                .await?
                                        {
                                            return Err(trc::SecurityEvent::AuthenticationBan
                                                .into_err()
                                                .details(
                                                    "Too many failed password change attempts.",
                                                )
                                                .ctx(trc::Key::RemoteIp, set.remote_ip)
                                                .ctx(
                                                    trc::Key::AccountName,
                                                    account.name().to_string(),
                                                ));
                                        } else {
                                            set.response.not_updated.append(
                                                id,
                                                SetError::forbidden().with_description(
                                                    "Current secret is incorrect.",
                                                ),
                                            );
                                            continue 'outer;
                                        }
                                    }

                                    if credential.secret != old_credential.secret {
                                        credential.secret = hash_secret(
                                            set.server
                                                .core
                                                .network
                                                .security
                                                .password_hash_algorithm,
                                            std::mem::take(&mut credential.secret),
                                        )
                                        .await
                                        .caused_by(trc::location!())?;
                                    }

                                    if credential.otp_auth != old_credential.otp_auth
                                        && !verify_otp_auth(
                                            credential.otp_auth.as_deref(),
                                            current_otp_code.as_deref(),
                                        )?
                                    {
                                        set.response.not_updated.append(
                                            id,
                                            SetError::forbidden()
                                                .with_description("OTP URL or token is invalid."),
                                        );
                                        continue 'outer;
                                    }
                                } else {
                                    set.response.not_updated.append(
                                        id,
                                        SetError::forbidden().with_description(
                                            "Current secret must be provided to change the password or OTP auth.",
                                        ),
                                    );
                                    continue 'outer;
                                }
                            }
                        }
                        (
                            Credential::AppPassword(credential),
                            Credential::AppPassword(old_credential),
                        )
                        | (Credential::ApiKey(credential), Credential::ApiKey(old_credential)) => {
                            // Paranoid check, this is verified in the patch implementation
                            if credential.secret != old_credential.secret {
                                set.response.not_updated.append(
                                    id,
                                    SetError::forbidden().with_description(
                                        "Cannot change the value of an app password or API key.",
                                    ),
                                );
                                continue 'outer;
                            }
                        }
                        _ => {}
                    }

                    set.response.updated.append(id, None);
                } else {
                    set.response.not_updated.append(id, SetError::not_found());
                }
            }

            // Process deletions
            for id in set.destroy.drain(..) {
                if let Some(idx) = account.credentials.0.inner.iter_mut().position(|c| {
                    c.value.credential_id() == id && !matches!(c.value, Credential::Password(_))
                }) {
                    account.credentials.inner_mut().inner.remove(idx);
                    set.response.destroyed.push(id);
                } else {
                    set.response.not_destroyed.append(id, SetError::not_found());
                }
            }
        }
        _ => unreachable!(),
    }

    if account != old_account {
        let mut cache_invalidator = CacheInvalidationBuilder::default();
        if account.encryption_at_rest != old_account.encryption_at_rest
            || account.description != old_account.description
            || account.locale != old_account.locale
        {
            cache_invalidator.invalidate(CacheInvalidation::Account(set.account_id));
        }
        if account.credentials != old_account.credentials {
            cache_invalidator.invalidate(CacheInvalidation::AccessToken(set.account_id));
        }

        let object = Object::new(ObjectInner::Account(Account::User(account)));
        let old_object = Object::with_revision(
            ObjectInner::Account(Account::User(old_account.clone())),
            revision,
        );

        match set
            .server
            .registry()
            .write(RegistryWrite::Update {
                object: &object,
                id: item_id,
                old_object: &old_object,
            })
            .await?
        {
            RegistryWriteResult::Success(_) => {
                // Invalidate caches
                set.server.invalidate_caches(cache_invalidator).await?;
            }
            err => {
                let err = map_write_error(err);
                let failed_create = set
                    .response
                    .created
                    .into_keys()
                    .map(|id| (id, err.clone()))
                    .collect::<Vec<_>>();
                let failed_update = set
                    .response
                    .updated
                    .into_keys()
                    .map(|id| (id, err.clone()))
                    .collect::<Vec<_>>();
                let failed_delete = set
                    .response
                    .destroyed
                    .into_iter()
                    .map(|id| (id, err.clone()))
                    .collect::<Vec<_>>();

                set.response.not_created.extend(failed_create);
                set.response.not_updated.extend(failed_update);
                set.response.not_destroyed.extend(failed_delete);
                set.response.created = Default::default();
                set.response.updated = Default::default();
                set.response.destroyed = Default::default();
            }
        }
    }

    Ok(set)
}

pub(crate) async fn account_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let Some(Account::User(account)) = get
        .server
        .registry()
        .object::<Account>(get.account_id.into())
        .await?
    else {
        return Ok(get.not_found_any());
    };

    match get.object_type {
        ObjectType::AccountSettings => {
            let mut ids = get
                .ids
                .take()
                .unwrap_or_else(|| vec![Id::singleton()])
                .into_iter();

            for id in ids.by_ref() {
                if id == Id::singleton() {
                    get.insert(
                        id,
                        AccountSettings {
                            encryption_at_rest: account.encryption_at_rest,
                            locale: account.locale,
                            description: account.description,
                        }
                        .into_value(),
                    );
                    break;
                } else {
                    get.not_found(id);
                }
            }

            get.response.not_found.extend(ids);
        }
        ObjectType::Credential => {
            let mut ids = if let Some(ids) = get.ids.take() {
                ids
            } else {
                account
                    .credentials
                    .values()
                    .map(|credential| credential.credential_id())
                    .collect::<Vec<_>>()
            };

            for mut credential in account.credentials {
                let id = match &mut credential {
                    Credential::Password(credential) => {
                        credential.allowed_ips.clear();
                        credential.credential_id
                    }
                    Credential::AppPassword(credential_properties) => {
                        credential_properties.credential_id
                    }
                    Credential::ApiKey(credential_properties) => {
                        credential_properties.credential_id
                    }
                };
                if ids.contains(&id) {
                    get.insert(id, credential.into_value());
                    ids.retain(|i| i != &id);
                }
            }

            for id in ids {
                get.not_found(id);
            }
        }
        _ => unreachable!(),
    }

    Ok(get)
}

pub(crate) async fn credential_query(
    mut query: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let Some(Account::User(account)) = query
        .server
        .registry()
        .object::<Account>(query.request.account_id)
        .await?
    else {
        return Err(trc::JmapEvent::Forbidden
            .into_err()
            .details("Account not found."));
    };

    let mut credential_type = None;
    let mut expires_at_filter = None;

    query
        .request
        .extract_filters(|property, op, value| match property {
            Property::Type => {
                if let Some(typ) = value.as_str().and_then(CredentialType::parse) {
                    credential_type = Some(typ);
                    true
                } else {
                    false
                }
            }
            Property::ExpiresAt => {
                if let Some(value) = value
                    .as_str()
                    .and_then(|value| UTCDateTime::from_str(value).ok())
                {
                    expires_at_filter = Some((op, value));
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let mut matches = Vec::new();
    for credential in account.credentials.iter() {
        if credential_type.is_none_or(|typ| credential.object_type() == typ) {
            let (credential_id, expires_at) = match credential {
                Credential::Password(credential) => {
                    (credential.credential_id, credential.expires_at)
                }
                Credential::AppPassword(credential) => {
                    (credential.credential_id, credential.expires_at)
                }
                Credential::ApiKey(credential) => (credential.credential_id, credential.expires_at),
            };
            if expires_at_filter.is_none_or(|(op, filter_value)| {
                expires_at.is_some_and(|expires_at| match op {
                    RegistryFilterOp::Equal => expires_at == filter_value,
                    RegistryFilterOp::GreaterThan => expires_at > filter_value,
                    RegistryFilterOp::GreaterEqualThan => expires_at >= filter_value,
                    RegistryFilterOp::LowerThan => expires_at < filter_value,
                    RegistryFilterOp::LowerEqualThan => expires_at <= filter_value,
                    RegistryFilterOp::TextMatch => false,
                })
            }) {
                matches.push((credential_id, expires_at));
            }
        }
    }

    let params = query
        .request
        .extract_parameters(query.server.core.jmap.query_max_results, None)?;

    match params.sort_by {
        Property::ExpiresAt => {
            if params.sort_ascending {
                matches.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            } else {
                matches.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            }
        }
        Property::Id => {
            if params.sort_ascending {
                matches.sort_by(|a, b| a.0.cmp(&b.0));
            } else {
                matches.sort_by(|a, b| b.0.cmp(&a.0));
            }
        }
        property => {
            return Err(trc::JmapEvent::UnsupportedSort.into_err().details(format!(
                "Property {} is not supported for sorting",
                property
            )));
        }
    }

    // Build response
    let mut response = QueryResponseBuilder::new(
        matches.len(),
        query.server.core.jmap.query_max_results,
        State::Initial,
        &query.request,
    );

    for (id, _) in matches {
        if !response.add_id(id) {
            break;
        }
    }

    Ok(response)
}

fn validate_credential_permissions(
    access_token: &AccessToken,
    credential: &SecondaryCredential,
) -> Result<(), SetError<Property>> {
    match &credential.permissions {
        CredentialPermissions::Inherit | CredentialPermissions::Disable(_) => Ok(()),
        CredentialPermissions::Replace(permissions) => access_token
            .can_grant_permissions(
                PermissionsGroup {
                    enabled: Permissions::from_permission(permissions.permissions.as_slice()),
                    disabled: Default::default(),
                    merge: false,
                }
                .finalize(),
            )
            .map_err(build_set_error),
    }
}
