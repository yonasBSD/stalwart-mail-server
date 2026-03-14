/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::CredentialType,
        prelude::{ObjectType, Property},
        structs::{Account, Credential, PasswordCredential, SecondaryCredential, UserAccount},
    },
    types::{EnumImpl, list::List},
};
use serde_json::json;

use crate::utils::server::TestServer;

pub async fn test(test: &TestServer) {
    let admin = test.account("admin@example.org");
    let domain_id = admin.find_or_create_domain("example.org").await;

    // Weak passwords should be rejected
    admin
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "12345".to_string(),
                ..Default::default()
            })]),
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_description_contains("Password must be at least 8 characters long.");
    admin
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "12345678".to_string(),
                ..Default::default()
            })]),
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_description_contains(concat!(
            "Password is too weak. This is a top-10 common password. ",
            "Add another word or two. Uncommon words are better."
        ));

    // Adding secondary credentials should not be allowed
    admin
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::AppPassword(SecondaryCredential {
                description: "Test app password".to_string(),
                ..Default::default()
            })]),
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_description_contains("Secondary credentials cannot be set directly");
    admin
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::ApiKey(SecondaryCredential {
                description: "Test API key".to_string(),
                ..Default::default()
            })]),
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_description_contains("Secondary credentials cannot be set directly");

    // Creating a user with a valid password should succeed
    let user_id = admin
        .registry_create_object(Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "this is a very strong password".to_string(),
                ..Default::default()
            })]),
            ..Default::default()
        }))
        .await;
    validate_password("user@example.org", "this is a very strong password", true).await;
    validate_password("user@example.org", "wrong password", false).await;

    // Change password as admin
    admin
        .registry_update_object_expect_err(
            ObjectType::Account,
            user_id,
            json!({
                "credentials/0/secret": "12345"
            }),
        )
        .await
        .assert_type(SetErrorType::InvalidProperties)
        .assert_description_contains("Password must be at least 8 characters long.");
    admin
        .registry_update_object(
            ObjectType::Account,
            user_id,
            json!({
                "credentials/0/secret": "very strong password indeed"
            }),
        )
        .await;
    validate_password("user@example.org", "this is a very strong password", false).await;
    validate_password("user@example.org", "very strong password indeed", true).await;

    // Change password as user
    let user = crate::utils::account::Account::new(
        "user@example.org",
        "very strong password indeed",
        &[],
        user_id,
    )
    .await;
    let credential_id = user
        .registry_query(
            ObjectType::Credential,
            [(Property::Type, CredentialType::Password.as_str())],
            Vec::<&str>::new(),
        )
        .await[0];

    // Password updates should require the old password
    user.registry_update_object_expect_err(
        ObjectType::Credential,
        credential_id,
        json!({
            Property::Secret: "12345"
        }),
    )
    .await
    .assert_type(SetErrorType::Forbidden)
    .assert_description_contains(
        "Current secret must be provided to change the password or OTP auth.",
    );

    user.registry_query(
        ObjectType::Credential,
        [(Property::Type, CredentialType::Password.as_str())],
        Vec::<&str>::new(),
    )
    .await[0];

    // Password policies should be enforced when changing password
    /*user.registry_update_object_expect_err(
        ObjectType::Credential,
        credential_id,
        json!({
            Property::CurrentSecret: "very strong password indeed",
            Property::Secret: "12345"
        }),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties)
    .assert_description_contains("Password must be at least 8 characters long.");*/
}

pub async fn validate_password(username: &str, password: &str, is_valid: bool) {
    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get("https://127.0.0.1:8899/.well-known/jmap")
        .basic_auth(username, Some(password))
        .send()
        .await
        .unwrap();

    let status = response.status();
    if status.is_success() != is_valid {
        let text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        panic!(
            "Expected password to be {}. Server responded with status {}: {}",
            if is_valid { "valid" } else { "invalid" },
            status,
            text
        );
    }
}
