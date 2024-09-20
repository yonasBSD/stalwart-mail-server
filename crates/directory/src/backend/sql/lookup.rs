/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::Credentials;
use store::{NamedRows, Rows, Value};
use trc::AddContext;

use crate::{
    backend::internal::{manage::ManageDirectory, PrincipalField, PrincipalValue},
    Principal, QueryBy, Type, ROLE_ADMIN, ROLE_USER,
};

use super::{SqlDirectory, SqlMappings};

impl SqlDirectory {
    pub async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> trc::Result<Option<Principal>> {
        let mut account_id = None;
        let account_name;
        let mut secret = None;

        let result = match by {
            QueryBy::Name(username) => {
                account_name = username.to_string();

                self.store
                    .query::<NamedRows>(&self.mappings.query_name, vec![username.into()])
                    .await
                    .caused_by(trc::location!())?
            }
            QueryBy::Id(uid) => {
                if let Some(username) = self
                    .data_store
                    .get_principal_name(uid)
                    .await
                    .caused_by(trc::location!())?
                {
                    account_name = username;
                } else {
                    return Ok(None);
                }
                account_id = Some(uid);

                self.store
                    .query::<NamedRows>(
                        &self.mappings.query_name,
                        vec![account_name.clone().into()],
                    )
                    .await
                    .caused_by(trc::location!())?
            }
            QueryBy::Credentials(credentials) => {
                let (username, secret_) = match credentials {
                    Credentials::Plain { username, secret } => (username, secret),
                    Credentials::OAuthBearer { token } => (token, token),
                    Credentials::XOauth2 { username, secret } => (username, secret),
                };
                account_name = username.to_string();
                secret = secret_.into();

                self.store
                    .query::<NamedRows>(&self.mappings.query_name, vec![username.into()])
                    .await
                    .caused_by(trc::location!())?
            }
        };

        if result.rows.is_empty() {
            return Ok(None);
        }

        // Map row to principal
        let mut principal = self
            .mappings
            .row_to_principal(result)
            .caused_by(trc::location!())?;

        // Validate password
        if let Some(secret) = secret {
            if !principal
                .verify_secret(secret)
                .await
                .caused_by(trc::location!())?
            {
                return Ok(None);
            }
        }

        // Obtain account ID if not available
        if let Some(account_id) = account_id {
            principal.id = account_id;
        } else {
            principal.id = self
                .data_store
                .get_or_create_principal_id(&account_name, Type::Individual)
                .await
                .caused_by(trc::location!())?;
        }
        principal.set(PrincipalField::Name, account_name);

        // Obtain members
        if return_member_of {
            if !self.mappings.query_members.is_empty() {
                for row in self
                    .store
                    .query::<Rows>(&self.mappings.query_members, vec![principal.name().into()])
                    .await
                    .caused_by(trc::location!())?
                    .rows
                {
                    if let Some(Value::Text(account_id)) = row.values.first() {
                        principal.append_int(
                            PrincipalField::MemberOf,
                            self.data_store
                                .get_or_create_principal_id(account_id, Type::Group)
                                .await
                                .caused_by(trc::location!())?,
                        );
                    }
                }
            }

            // Obtain roles
            let mut did_role_cleanup = false;
            for member in self
                .data_store
                .get_member_of(principal.id)
                .await
                .caused_by(trc::location!())?
            {
                match member.typ {
                    Type::List => {
                        principal.append_int(PrincipalField::Lists, member.principal_id);
                    }
                    Type::Role => {
                        if !did_role_cleanup {
                            principal.remove(PrincipalField::Roles);
                            did_role_cleanup = true;
                        }
                        principal.append_int(PrincipalField::Roles, member.principal_id);
                    }
                    _ => {
                        principal.append_int(PrincipalField::MemberOf, member.principal_id);
                    }
                }
            }
        }

        // Obtain emails
        if !self.mappings.query_emails.is_empty() {
            principal.set(
                PrincipalField::Emails,
                PrincipalValue::StringList(
                    self.store
                        .query::<Rows>(&self.mappings.query_emails, vec![principal.name().into()])
                        .await
                        .caused_by(trc::location!())?
                        .into(),
                ),
            );
        }

        Ok(Some(principal))
    }

    pub async fn email_to_ids(&self, address: &str) -> trc::Result<Vec<u32>> {
        let names = self
            .store
            .query::<Rows>(&self.mappings.query_recipients, vec![address.into()])
            .await
            .caused_by(trc::location!())?;

        let mut ids = Vec::with_capacity(names.rows.len());

        for row in names.rows {
            if let Some(Value::Text(name)) = row.values.first() {
                ids.push(
                    self.data_store
                        .get_or_create_principal_id(name, Type::Individual)
                        .await
                        .caused_by(trc::location!())?,
                );
            }
        }

        Ok(ids)
    }

    pub async fn rcpt(&self, address: &str) -> trc::Result<bool> {
        self.store
            .query::<bool>(
                &self.mappings.query_recipients,
                vec![address.to_string().into()],
            )
            .await
            .map_err(Into::into)
    }

    pub async fn vrfy(&self, address: &str) -> trc::Result<Vec<String>> {
        self.store
            .query::<Rows>(
                &self.mappings.query_verify,
                vec![address.to_string().into()],
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn expn(&self, address: &str) -> trc::Result<Vec<String>> {
        self.store
            .query::<Rows>(
                &self.mappings.query_expand,
                vec![address.to_string().into()],
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn is_local_domain(&self, domain: &str) -> trc::Result<bool> {
        self.store
            .query::<bool>(&self.mappings.query_domains, vec![domain.into()])
            .await
            .map_err(Into::into)
    }
}

impl SqlMappings {
    pub fn row_to_principal(&self, rows: NamedRows) -> trc::Result<Principal> {
        let mut principal = Principal::default();
        let mut role = ROLE_USER;

        if let Some(row) = rows.rows.into_iter().next() {
            for (name, value) in rows.names.into_iter().zip(row.values) {
                if self
                    .column_secret
                    .iter()
                    .any(|c| name.eq_ignore_ascii_case(c))
                {
                    if let Value::Text(secret) = value {
                        principal.append_str(PrincipalField::Secrets, secret.into_owned());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_type) {
                    match value.to_str().as_ref() {
                        "individual" | "person" | "user" => {
                            principal.typ = Type::Individual;
                        }
                        "group" => principal.typ = Type::Group,
                        "admin" | "superuser" | "administrator" => {
                            principal.typ = Type::Individual;
                            role = ROLE_ADMIN;
                        }
                        _ => (),
                    }
                } else if name.eq_ignore_ascii_case(&self.column_description) {
                    if let Value::Text(text) = value {
                        principal.set(PrincipalField::Description, text.into_owned());
                    }
                } else if name.eq_ignore_ascii_case(&self.column_quota) {
                    if let Value::Integer(quota) = value {
                        principal.set(PrincipalField::Quota, quota as u64);
                    }
                }
            }
        }

        Ok(principal.with_field(PrincipalField::Roles, role))
    }
}
