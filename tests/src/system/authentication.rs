/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use common::auth::credential::{ApiKey, AppPassword};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{CredentialType, StorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            Account, Credential, Http, PasswordCredential, SecondaryCredential, UserAccount,
        },
    },
    types::{EnumImpl, ipmask::IpAddrOrMask, list::List, map::Map},
};
use serde_json::json;
use std::str::FromStr;

pub async fn test(test: &TestServer) {
    let admin = test.account("admin@example.org");
    let domain_id = admin.find_or_create_domain("example.org").await;

    // Enable X-Forwarded-For processing to test IP-based access restrictions
    admin
        .registry_update_setting(
            Http {
                use_x_forwarded: true,
                ..Default::default()
            },
            &[Property::UseXForwarded],
        )
        .await;
    admin.reload_settings().await;

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
    let mut user = crate::utils::account::Account::new(
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

    // Password policies should be enforced when changing password
    user.registry_update_object_expect_err(
        ObjectType::Credential,
        credential_id,
        json!({
            Property::CurrentSecret: "very strong password indeed",
            Property::Secret: "12345"
        }),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties)
    .assert_description_contains("Password must be at least 8 characters long.");

    // Perform a valid password update
    user.registry_update_object(
        ObjectType::Credential,
        credential_id,
        json!({
            Property::CurrentSecret: "very strong password indeed",
            Property::Secret: "user provided strong password"
        }),
    )
    .await;
    validate_password("user@example.org", "very strong password indeed", false).await;
    validate_password("user@example.org", "user provided strong password", true).await;
    user.update_secret("user provided strong password");

    // Users should not be allowed to change allowedIps of expiration
    user.registry_update_object_expect_err(
        ObjectType::Credential,
        credential_id,
        json!({
            Property::CurrentSecret: "user provided strong password",
            Property::ExpiresAt: "2029-01-01T00:00:00Z"
        }),
    )
    .await
    .assert_type(SetErrorType::Forbidden)
    .assert_description_contains("Modifying allowed IPs or expiration is not allowed.");

    user.registry_update_object_expect_err(
        ObjectType::Credential,
        credential_id,
        json!({
            Property::CurrentSecret: "user provided strong password",
            Property::AllowedIps: {"192.168.1.1": true}
        }),
    )
    .await
    .assert_type(SetErrorType::Forbidden)
    .assert_description_contains("Modifying allowed IPs or expiration is not allowed.");

    // Users should not be allowed to destroy their own credentials
    user.registry_destroy_object_expect_err(ObjectType::Credential, credential_id)
        .await
        .assert_type(SetErrorType::Forbidden)
        .assert_description_contains("Users are not allowed to destroy their own credentials.");

    // Limit login to specific IPs and set credential quotas
    admin
        .registry_update_object(
            ObjectType::Account,
            user_id,
            json!({
                "credentials/0/allowedIps": {"192.168.1.1": true},
                Property::Quotas: {
                    StorageQuota::MaxApiKeys.as_str(): 1,
                    StorageQuota::MaxAppPasswords.as_str(): 1,
                 }
            }),
        )
        .await;
    validate_password_with_ip(
        "user@example.org",
        "user provided strong password",
        "192.168.1.1",
        true,
    )
    .await;
    validate_password_with_ip(
        "user@example.org",
        "user provided strong password",
        "192.168.1.2",
        false,
    )
    .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            user_id,
            json!({
                "credentials/0/allowedIps": {},
            }),
        )
        .await;

    // Create an IP-restricted App Password and verify it works
    let response = user
        .registry_create([Credential::AppPassword(SecondaryCredential {
            allowed_ips: Map::new(vec![IpAddrOrMask::from_str("10.0.0.2").unwrap()]),
            description: "My app password".to_string(),
            ..Default::default()
        })])
        .await;
    let app_password = response.created(0);
    let app_password_id = app_password.object_id();
    let app_password_secret = app_password.text_field("secret").to_string();
    let _ = AppPassword::parse(&app_password_secret).unwrap();
    validate_password_with_ip("user@example.org", &app_password_secret, "10.0.0.2", true).await;
    validate_password_with_ip("user@example.org", &app_password_secret, "10.0.0.3", false).await;

    // Create an IP-restricted API key and verify it works
    let response = user
        .registry_create([Credential::ApiKey(SecondaryCredential {
            allowed_ips: Map::new(vec![IpAddrOrMask::from_str("10.0.0.2").unwrap()]),
            description: "My API key".to_string(),
            ..Default::default()
        })])
        .await;
    let api_key = response.created(0);
    let api_key_id = api_key.object_id();
    let api_key_secret = api_key.text_field("secret").to_string();
    let _ = ApiKey::parse(&api_key_secret).unwrap();
    validate_token_with_ip(&api_key_secret, "10.0.0.2", true).await;
    validate_token_with_ip(&api_key_secret, "10.0.0.3", false).await;

    // Creating more API keys or app passwords should fail due to quota
    user.registry_create_object_expect_err(Credential::AppPassword(SecondaryCredential {
        description: "Another app password".to_string(),
        ..Default::default()
    }))
    .await
    .assert_type(SetErrorType::OverQuota)
    .assert_description_contains("You have exceeded your quota of 1 app passwords.");
    user.registry_create_object_expect_err(Credential::ApiKey(SecondaryCredential {
        description: "Another API key".to_string(),
        ..Default::default()
    }))
    .await
    .assert_type(SetErrorType::OverQuota)
    .assert_description_contains("You have exceeded your quota of 1 API keys.");

    // Destroy the API key and app password, then verify they no longer work
    let response = user
        .registry_destroy(ObjectType::Credential, [app_password_id, api_key_id])
        .await;
    assert_eq!(
        vec![app_password_id, api_key_id],
        response.destroyed_ids().collect::<Vec<_>>()
    );
    validate_token_with_ip(&api_key_secret, "10.0.0.2", false).await;
    validate_password_with_ip("user@example.org", &app_password_secret, "10.0.0.2", false).await;
    validate_password("user@example.org", "user provided strong password", true).await;

    // Clean up
    assert_eq!(
        admin
            .registry_destroy(ObjectType::Account, [user_id])
            .await
            .destroyed_ids()
            .collect::<Vec<_>>(),
        vec![user_id]
    );
    validate_password("user@example.org", "user provided strong password", false).await;
}

async fn validate_password(username: &str, password: &str, is_valid: bool) {
    validate_password_with_ip(username, password, "127.0.0.1", is_valid).await;
}

async fn validate_password_with_ip(
    username: &str,
    password: &str,
    remote_ip: &str,
    is_valid: bool,
) {
    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get("https://127.0.0.1:8899/.well-known/jmap")
        .basic_auth(username, Some(password))
        .header("X-Forwarded-For", remote_ip)
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

async fn validate_token_with_ip(token: &str, remote_ip: &str, is_valid: bool) {
    let response = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get("https://127.0.0.1:8899/.well-known/jmap")
        .bearer_auth(token)
        .header("X-Forwarded-For", remote_ip)
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
            "Expected token to be {}. Server responded with status {}: {}",
            if is_valid { "valid" } else { "invalid" },
            status,
            text
        );
    }
}
