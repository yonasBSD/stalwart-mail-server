/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::Store;
use utils::config::{utils::AsKey, Config};

use crate::{
    backend::internal::{manage::ManageDirectory, PrincipalField},
    Principal, Type, ROLE_ADMIN, ROLE_USER,
};

use super::{EmailType, MemoryDirectory};

impl MemoryDirectory {
    pub async fn from_config(
        config: &mut Config,
        prefix: impl AsKey,
        data_store: Store,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let mut directory = MemoryDirectory {
            data_store,
            principals: Default::default(),
            emails_to_ids: Default::default(),
            domains: Default::default(),
        };

        for lookup_id in config
            .sub_keys((prefix.as_str(), "principals"), ".name")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
        {
            let lookup_id = lookup_id.as_str();
            let name = config
                .value_require((prefix.as_str(), "principals", lookup_id, "name"))?
                .to_string();
            let (typ, is_superuser) =
                match config.value((prefix.as_str(), "principals", lookup_id, "class")) {
                    Some("individual") => (Type::Individual, false),
                    Some("admin") => (Type::Individual, true),
                    Some("group") => (Type::Group, false),
                    _ => (Type::Individual, false),
                };

            // Obtain id
            let id = directory
                .data_store
                .get_or_create_principal_id(&name, Type::Individual)
                .await
                .map_err(|err| {
                    config.new_build_error(
                        prefix.as_str(),
                        format!(
                            "Failed to obtain id for principal {} ({}): {:?}",
                            name, lookup_id, err
                        ),
                    )
                })
                .ok()?;

            // Create principal
            let mut principal = Principal {
                id,
                typ,
                ..Default::default()
            }
            .with_field(
                PrincipalField::Roles,
                if is_superuser { ROLE_ADMIN } else { ROLE_USER },
            );

            // Obtain group ids
            for group in config
                .values((prefix.as_str(), "principals", lookup_id, "member-of"))
                .map(|(_, s)| s.to_string())
                .collect::<Vec<_>>()
            {
                principal.append_int(
                    PrincipalField::MemberOf,
                    directory
                        .data_store
                        .get_or_create_principal_id(&group, Type::Group)
                        .await
                        .map_err(|err| {
                            config.new_build_error(
                                prefix.as_str(),
                                format!(
                                    "Failed to obtain id for principal {} ({}): {:?}",
                                    name, lookup_id, err
                                ),
                            )
                        })
                        .ok()?,
                );
            }

            // Parse email addresses
            for (pos, (_, email)) in config
                .values((prefix.as_str(), "principals", lookup_id, "email"))
                .enumerate()
            {
                directory
                    .emails_to_ids
                    .entry(email.to_string())
                    .or_default()
                    .push(if pos > 0 {
                        EmailType::Alias(id)
                    } else {
                        EmailType::Primary(id)
                    });

                if let Some((_, domain)) = email.rsplit_once('@') {
                    directory.domains.insert(domain.to_lowercase());
                }

                principal.append_str(PrincipalField::Emails, email.to_lowercase());
            }

            // Parse mailing lists
            for (_, email) in
                config.values((prefix.as_str(), "principals", lookup_id, "email-list"))
            {
                directory
                    .emails_to_ids
                    .entry(email.to_lowercase())
                    .or_default()
                    .push(EmailType::List(id));
                if let Some((_, domain)) = email.rsplit_once('@') {
                    directory.domains.insert(domain.to_lowercase());
                }
            }

            principal.set(PrincipalField::Name, name.clone());
            for (_, secret) in config.values((prefix.as_str(), "principals", lookup_id, "secret")) {
                principal.append_str(PrincipalField::Secrets, secret.to_string());
            }
            if let Some(description) =
                config.value((prefix.as_str(), "principals", lookup_id, "description"))
            {
                principal.set(PrincipalField::Description, description.to_string());
            }
            if let Some(quota) =
                config.property::<u64>((prefix.as_str(), "principals", lookup_id, "quota"))
            {
                principal.set(PrincipalField::Quota, quota);
            }

            directory.principals.push(principal);
        }

        Some(directory)
    }
}
