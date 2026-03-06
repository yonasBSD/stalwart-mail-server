/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, RegistrySetResponse, ValidationResult};
use common::storage::encryption::parse_public_key;
use jmap_proto::error::set::SetError;
use registry::schema::{
    enums::StorageQuota,
    prelude::{ObjectType, Property},
    structs::PublicKey,
};
use store::registry::RegistryQuery;

pub(crate) async fn validate_public_key(
    set: &RegistrySetResponse<'_>,
    key: &mut PublicKey,
    old_key: Option<&PublicKey>,
) -> ValidationResult {
    let response = ObjectResponse::default();

    if let Some(old_key) = old_key {
        if key.key == old_key.key {
            return Ok(Ok(response));
        }
    } else {
        // Validate quotas
        let num_masked = set
            .server
            .registry()
            .count(RegistryQuery::new(ObjectType::PublicKey).with_account(set.account_id))
            .await? as u32;
        let account = set.server.account(set.account_id).await?;
        let masked_quota = set
            .server
            .object_quota(account.object_quotas(), StorageQuota::MaxPublicKeys);
        if num_masked >= masked_quota {
            return Ok(Err(SetError::over_quota().with_description(format!(
                "You have exceeded your quota of {} public keys.",
                masked_quota
            ))));
        }
    }

    match parse_public_key(key) {
        Ok(Some(_)) => Ok(Ok(response)),
        Ok(None) => Ok(Err(SetError::invalid_properties()
            .with_property(Property::Key)
            .with_description("No valid public key found."))),
        Err(err) => Ok(Err(SetError::invalid_properties()
            .with_property(Property::Key)
            .with_description(err.into_owned()))),
    }
}
