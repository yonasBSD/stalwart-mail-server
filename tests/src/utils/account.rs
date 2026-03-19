/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{imap::ImapConnection, server::TestServer, webdav::DummyWebDavClient};
use ahash::AHashMap;
use jmap_client::client::{Client, Credentials};
use registry::{
    schema::{
        prelude::{ObjectType, Property},
        structs::{
            self, Credential, CustomRoles, Domain, EmailAlias, PasswordCredential, Roles,
            UserAccount,
        },
    },
    types::{list::List, map::Map},
};
use serde_json::json;
use std::time::Duration;
use types::id::Id;

pub struct Account {
    name: &'static str,
    secret: &'static str,
    emails: &'static [&'static str],
    id: Id,
    id_string: String,
}

impl TestServer {
    pub async fn create_user_account(
        &self,
        using_account: &str,
        name: &'static str,
        secret: &'static str,
        aliases: &'static [&'static str],
    ) -> Account {
        let mut domains = AHashMap::from_iter(
            aliases
                .iter()
                .copied()
                .chain([name].into_iter())
                .map(|email| {
                    let domain = email.split('@').nth(1).expect("Invalid email address");
                    (domain, Id::singleton())
                }),
        );
        let account = self.account(using_account);
        for (name, id) in &mut domains {
            *id = account.find_or_create_domain(name).await;
        }
        let (account_name, domain_id) = name
            .rsplit_once('@')
            .map(|(name, domain)| (name.to_string(), *domains.get(domain).unwrap()))
            .unwrap();
        let account_aliases = aliases.iter().map(|email| {
            let (name, domain_id) = email
                .rsplit_once('@')
                .map(|(name, domain)| (name.to_string(), *domains.get(domain).unwrap()))
                .unwrap();
            EmailAlias {
                name,
                domain_id,
                enabled: true,
                ..Default::default()
            }
        });

        let account_id = account
            .registry_create_object(structs::Account::User(UserAccount {
                name: account_name,
                domain_id,
                credentials: List::from_iter([Credential::Password(PasswordCredential {
                    secret: secret.to_string(),
                    ..Default::default()
                })]),
                aliases: List::from_iter(account_aliases),
                ..Default::default()
            }))
            .await;

        Account::new(name, secret, aliases, account_id)
    }

    pub fn insert_account(&mut self, account: Account) {
        self.accounts.insert(account.name(), account);
    }
}

impl Account {
    pub fn new(
        name: &'static str,
        secret: &'static str,
        emails: &'static [&'static str],
        id: Id,
    ) -> Self {
        Self {
            name,
            secret,
            emails,
            id,
            id_string: id.to_string(),
        }
    }

    pub fn update_secret(&mut self, new_secret: &'static str) {
        self.secret = new_secret;
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn id_string(&self) -> &str {
        &self.id_string
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn secret(&self) -> &'static str {
        self.secret
    }

    pub fn emails(&self) -> &'static [&'static str] {
        self.emails
    }

    pub async fn find_or_create_domain(&self, name: &'static str) -> Id {
        let ids = self
            .registry_query_ids(
                ObjectType::Domain,
                [(Property::Name, name)],
                Vec::<&str>::new(),
            )
            .await;

        match ids.len() {
            0 => self.create_domain(name).await,
            1 => ids[0],
            _ => panic!("Multiple domains with name {name} found"),
        }
    }

    pub async fn create_domain(&self, name: &'static str) -> Id {
        self.registry_create_object(Domain {
            is_enabled: true,
            name: name.to_string(),
            ..Default::default()
        })
        .await
    }

    pub async fn assign_roles_to_account(&self, account_id: Id, names: &[&str]) {
        let mut role_ids = Vec::new();
        for name in names {
            let role_id = *self
                .registry_query_ids(
                    ObjectType::Role,
                    [(Property::Description, *name)],
                    Vec::<&str>::new(),
                )
                .await
                .first()
                .unwrap_or_else(|| panic!("Role {name} not found"));
            role_ids.push(role_id);
        }

        self.registry_update(
            ObjectType::Account,
            [(
                account_id,
                json!({
                    Property::Roles: Roles::Custom(CustomRoles { role_ids: Map::new(role_ids) })
                }),
            )],
        )
        .await
        .updated_id(account_id);
    }

    pub fn webdav_client(&self) -> DummyWebDavClient {
        DummyWebDavClient::new(
            self.id.document_id(),
            self.name(),
            self.secret(),
            self.emails()[0],
        )
    }

    pub async fn imap_client(&self) -> ImapConnection {
        let mut imap = ImapConnection::connect(b"_x ").await;
        imap.authenticate(self.name(), self.secret()).await;
        imap
    }

    pub async fn jmap_client(&self) -> Client {
        let mut client = Client::new()
            .credentials(Credentials::basic(self.name(), self.secret()))
            .timeout(Duration::from_secs(3600))
            .accept_invalid_certs(true)
            .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await
            .unwrap();
        client.set_default_account_id(self.id_string());
        client
    }
}
