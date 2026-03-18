/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::{BuildAccessToken, permissions::DefaultPermissions};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::{
            self, AccountSettings, Credential, CustomRoles, PasswordCredential, Role, UserAccount,
            UserRoles,
        },
    },
    types::{EnumImpl, list::List, map::Map},
};
use serde_json::json;
use types::id::Id;

use crate::utils::{jmap::JmapUtils, server::TestServer};

pub async fn test(test: &mut TestServer) {
    println!("Running authorization tests...");

    let admin = test.account("admin@example.org");
    let domain_id = admin.find_or_create_domain("example.org").await;

    // Create nested roles
    let l3_role_id = admin
        .registry_create_object(Role {
            description: "Level 3 role".to_string(),
            enabled_permissions: Map::new(vec![Permission::SysAccountSettingsGet]),
            ..Default::default()
        })
        .await;
    let l2_role_id = admin
        .registry_create_object(Role {
            description: "Level 2 role".to_string(),
            enabled_permissions: Map::new(vec![
                Permission::AuthenticateWithAlias,
                Permission::SysAccountSettingsUpdate,
            ]),
            role_ids: Map::new(vec![l3_role_id]),
            ..Default::default()
        })
        .await;
    let l1_role_id = admin
        .registry_create_object(Role {
            description: "Level 1 role".to_string(),
            enabled_permissions: Map::new(vec![Permission::Authenticate]),
            role_ids: Map::new(vec![l2_role_id]),
            ..Default::default()
        })
        .await;

    // Create a user with the nested role
    let user_id = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "this is a very strong password".to_string(),
                ..Default::default()
            })]),
            roles: UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![l1_role_id]),
            }),
            ..Default::default()
        }))
        .await;
    let user = crate::utils::account::Account::new(
        "user@example.org",
        "this is a very strong password",
        &[],
        user_id,
    );

    // Verify user permissions include all permissions from the nested roles
    user.registry_update_object(
        ObjectType::AccountSettings,
        Id::singleton(),
        json!({
            Property::Description: "Updated description"
        }),
    )
    .await;
    assert_eq!(
        user.registry_get::<AccountSettings>(Id::singleton())
            .await
            .description
            .as_deref(),
        Some("Updated description")
    );

    // Remove read permissions from the l3 role and verify the user can no longer read account settings
    admin
        .registry_update_object(
            ObjectType::Role,
            l3_role_id,
            json!({
                Property::EnabledPermissions: {}
            }),
        )
        .await;
    assert_eq!(
        user.registry_get_many(ObjectType::AccountSettings, [Id::singleton()])
            .await
            .method_response()
            .text_field("type"),
        "forbidden"
    );

    // User should still be able to update account settings due to permissions from the l2 role
    user.registry_update_object(
        ObjectType::AccountSettings,
        Id::singleton(),
        json!({
            Property::Description: "Updated description v2"
        }),
    )
    .await;

    // Disable account settings update permission in the l3 role
    admin
        .registry_update_object(
            ObjectType::Role,
            l3_role_id,
            json!({
                Property::DisabledPermissions: Map::new(vec![Permission::SysAccountSettingsUpdate]),
            }),
        )
        .await;
    assert_eq!(
        user.registry_update(
            ObjectType::AccountSettings,
            [(
                Id::singleton(),
                json!({
                    Property::Description: "Updated description v3"
                })
            )]
        )
        .await
        .method_response()
        .text_field("type"),
        "forbidden"
    );

    // Assign user to the default user role
    admin
        .registry_update_object(
            ObjectType::Account,
            user_id,
            json!({
                Property::Roles: UserRoles::User
            }),
        )
        .await;

    // Make sure the user does not have any administrator permissions
    let permissions = DefaultPermissions::default();
    let mut num_permissions_verified = 0;
    let mut num_objects_verified = 0;
    let user_access_token = test
        .server
        .access_token(user_id.document_id())
        .await
        .unwrap()
        .build();
    for permission in permissions.superuser {
        if permissions.user.contains(&permission) {
            continue;
        }
        num_permissions_verified += 1;
        assert!(
            !user_access_token.has_permission(permission),
            "User should not have {:?} permission",
            permission
        );

        if let Some(name) = permission
            .as_str()
            .strip_prefix("sys")
            .and_then(|perm| perm.strip_suffix("Get"))
        {
            let object_type = ObjectType::parse(name).unwrap();

            assert_eq!(
                user.registry_get_many(object_type, Vec::<&str>::new())
                    .await
                    .method_response()
                    .text_field("type"),
                "forbidden",
                "User should not have permission to read {:?} objects",
                object_type
            );

            num_objects_verified += 1;
        }
    }
    assert_ne!(
        num_permissions_verified, 0,
        "No permissions were verified in the test"
    );
    assert_ne!(
        num_objects_verified, 0,
        "No object read permissions were verified in the test"
    );

    // Deleting a linked role should not be allowed
    admin
        .registry_destroy_object_expect_err(ObjectType::Role, l2_role_id)
        .await
        .assert_type(SetErrorType::ObjectIsLinked);

    // Delete the account and roles in the correct order
    admin.destroy_account(user).await;
    for role_id in [l1_role_id, l2_role_id, l3_role_id] {
        admin
            .registry_destroy(ObjectType::Role, [role_id])
            .await
            .assert_destroyed(&[role_id]);
    }

    test.assert_is_empty().await;
}
