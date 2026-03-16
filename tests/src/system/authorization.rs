/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;

pub async fn test(test: &mut TestServer) {
    println!("Running authorization tests...");

    /*

        pub async fn test(params: &JMAPTest) {
        println!("Running permissions tests...");
        let server = params.server.clone();

        // Disable spam filtering to avoid adding extra headers
        let old_core = params.server.core.clone();
        let mut new_core = old_core.as_ref().clone();
        new_core.spam.enabled = false;
        new_core.smtp.session.data.add_delivered_to = false;
        params.server.inner.shared_core.store(Arc::new(new_core));

        // Remove unlimited requests permission
        for &account in params.accounts.keys() {
            params
                .server
                .store()
                .remove_permissions(account, [Permission::UnlimitedRequests])
                .await;
        }

        // Prepare management API
        let api = ManagementApi::new(8899, "admin", "secret");

        // Create a user with the default 'user' role
        let account_id = api
            .post::<u32>(
                "/api/principal",
                &PrincipalSet::new(u32::MAX, Type::Individual)
                    .with_field(PrincipalField::Name, "role_player")
                    .with_field(PrincipalField::Roles, vec!["user".to_string()])
                    .with_field(
                        PrincipalField::DisabledPermissions,
                        vec![Permission::Pop3Dele.name().to_string()],
                    ),
            )
            .await
            .unwrap()
            .unwrap_data();
        let revision = server
            .get_access_token(account_id)
            .await
            .unwrap()
            .validate_permissions(
                Permission::all().filter(|p| p.is_user_permission() && *p != Permission::Pop3Dele),
            )
            .revision;

        // Create multiple roles
        for (role, permissions, parent_role) in &[
            (
                "pop3_user",
                vec![Permission::Pop3Authenticate, Permission::Pop3List],
                vec![],
            ),
            (
                "imap_user",
                vec![Permission::ImapAuthenticate, Permission::ImapList],
                vec![],
            ),
            (
                "jmap_user",
                vec![
                    Permission::JmapEmailQuery,
                    Permission::AuthenticateOauth,
                    Permission::ManageEncryption,
                ],
                vec![],
            ),
            (
                "email_user",
                vec![Permission::EmailSend, Permission::EmailReceive],
                vec!["pop3_user", "imap_user", "jmap_user"],
            ),
        ] {
            api.post::<u32>(
                "/api/principal",
                &PrincipalSet::new(u32::MAX, Type::Role)
                    .with_field(PrincipalField::Name, role.to_string())
                    .with_field(
                        PrincipalField::EnabledPermissions,
                        permissions
                            .iter()
                            .map(|p| p.name().to_string())
                            .collect::<Vec<_>>(),
                    )
                    .with_field(
                        PrincipalField::Roles,
                        parent_role
                            .iter()
                            .map(|r| r.to_string())
                            .collect::<Vec<_>>(),
                    ),
            )
            .await
            .unwrap()
            .unwrap_data();
        }

        // Update email_user role
        api.patch::<()>(
            "/api/principal/email_user",
            &vec![PrincipalUpdate::add_item(
                PrincipalField::DisabledPermissions,
                PrincipalValue::String(Permission::ManageEncryption.name().to_string()),
            )],
        )
        .await
        .unwrap()
        .unwrap_data();

        // Update the user role to the nested 'email_user' role
        api.patch::<()>(
            "/api/principal/role_player",
            &vec![PrincipalUpdate::set(
                PrincipalField::Roles,
                PrincipalValue::StringList(vec!["email_user".to_string()]),
            )],
        )
        .await
        .unwrap()
        .unwrap_data();
        assert_ne!(
            server
                .get_access_token(account_id)
                .await
                .unwrap()
                .validate_permissions([
                    Permission::EmailSend,
                    Permission::EmailReceive,
                    Permission::JmapEmailQuery,
                    Permission::AuthenticateOauth,
                    Permission::ImapAuthenticate,
                    Permission::ImapList,
                    Permission::Pop3Authenticate,
                    Permission::Pop3List,
                ])
                .revision,
            revision
        );

        // Query all principals
        api.get::<List<PrincipalSet>>("/api/principal")
            .await
            .unwrap()
            .unwrap_data()
            .assert_count(12)
            .assert_exists(
                "admin",
                Type::Individual,
                [
                    (PrincipalField::Roles, &["admin"][..]),
                    (PrincipalField::Members, &[][..]),
                    (PrincipalField::EnabledPermissions, &[][..]),
                    (PrincipalField::DisabledPermissions, &[][..]),
                ],
            )
            .assert_exists(
                "role_player",
                Type::Individual,
                [
                    (PrincipalField::Roles, &["email_user"][..]),
                    (PrincipalField::Members, &[][..]),
                    (PrincipalField::EnabledPermissions, &[][..]),
                    (
                        PrincipalField::DisabledPermissions,
                        &[Permission::Pop3Dele.name()][..],
                    ),
                ],
            )
            .assert_exists(
                "email_user",
                Type::Role,
                [
                    (
                        PrincipalField::Roles,
                        &["pop3_user", "imap_user", "jmap_user"][..],
                    ),
                    (PrincipalField::Members, &["role_player"][..]),
                    (
                        PrincipalField::EnabledPermissions,
                        &[
                            Permission::EmailReceive.name(),
                            Permission::EmailSend.name(),
                        ][..],
                    ),
                    (
                        PrincipalField::DisabledPermissions,
                        &[Permission::ManageEncryption.name()][..],
                    ),
                ],
            )
            .assert_exists(
                "pop3_user",
                Type::Role,
                [
                    (PrincipalField::Roles, &[][..]),
                    (PrincipalField::Members, &["email_user"][..]),
                    (
                        PrincipalField::EnabledPermissions,
                        &[
                            Permission::Pop3Authenticate.name(),
                            Permission::Pop3List.name(),
                        ][..],
                    ),
                    (PrincipalField::DisabledPermissions, &[][..]),
                ],
            )
            .assert_exists(
                "imap_user",
                Type::Role,
                [
                    (PrincipalField::Roles, &[][..]),
                    (PrincipalField::Members, &["email_user"][..]),
                    (
                        PrincipalField::EnabledPermissions,
                        &[
                            Permission::ImapAuthenticate.name(),
                            Permission::ImapList.name(),
                        ][..],
                    ),
                    (PrincipalField::DisabledPermissions, &[][..]),
                ],
            )
            .assert_exists(
                "jmap_user",
                Type::Role,
                [
                    (PrincipalField::Roles, &[][..]),
                    (PrincipalField::Members, &["email_user"][..]),
                    (
                        PrincipalField::EnabledPermissions,
                        &[
                            Permission::JmapEmailQuery.name(),
                            Permission::AuthenticateOauth.name(),
                            Permission::ManageEncryption.name(),
                        ][..],
                    ),
                    (PrincipalField::DisabledPermissions, &[][..]),
                ],
            );

        // Verify permissions
        server
            .get_access_token(tenant_admin_id)
            .await
            .unwrap()
            .validate_permissions(Permission::all().filter(|p| p.is_tenant_admin_permission()))
            .validate_tenant(tenant_id, TENANT_QUOTA);

        // Prepare tenant admin API
        let tenant_api = ManagementApi::new(8899, "admin@foobar.org", "mytenantpass");

        // John should not be allowed to receive email
        let (message_blob, _) = server
            .put_temporary_blob(tenant_user_id, TEST_MESSAGE.as_bytes(), 60)
            .await
            .unwrap();
        assert_eq!(
            server
                .deliver_message(IngestMessage {
                    sender_address: "bill@foobar.org".to_string(),
                    sender_authenticated: true,
                    recipients: vec![IngestRecipient {
                        address: "john@foobar.org".to_string(),
                        is_spam: false
                    }],
                    message_blob: message_blob.clone(),
                    message_size: TEST_MESSAGE.len() as u64,
                    session_id: 0,
                })
                .await
                .status,
            vec![LocalDeliveryStatus::PermanentFailure {
                code: [5, 5, 0],
                reason: "This account is not authorized to receive email.".into()
            }]
        );

        // Remove the restriction
        tenant_api
            .patch::<()>(
                "/api/principal/john.doe@foobar.org",
                &vec![PrincipalUpdate::remove_item(
                    PrincipalField::Roles,
                    PrincipalValue::String("no-mail-for-you@foobar.com".to_string()),
                )],
            )
            .await
            .unwrap()
            .unwrap_data();
        server
            .get_access_token(tenant_user_id)
            .await
            .unwrap()
            .validate_permissions(
                Permission::all().filter(|p| p.is_tenant_admin_permission() || p.is_user_permission()),
            );
    }

    const TENANT_QUOTA: u64 = TEST_MESSAGE.len() as u64;
    const TEST_MESSAGE: &str = concat!(
        "From: bill@foobar.org\r\n",
        "To: jdoe@foobar.com\r\n",
        "Subject: TPS Report\r\n",
        "\r\n",
        "I'm going to need those TPS reports ASAP. ",
        "So, if you could do that, that'd be great."
    );

    trait ValidatePrincipalList {
        fn assert_exists<'x>(
            self,
            name: &str,
            typ: Type,
            items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
        ) -> Self;
        fn assert_count(self, count: usize) -> Self;
    }

    impl ValidatePrincipalList for List<PrincipalSet> {
        fn assert_exists<'x>(
            self,
            name: &str,
            typ: Type,
            items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
        ) -> Self {
            for item in &self.items {
                if item.name() == name {
                    item.validate(typ, items);
                    return self;
                }
            }

            panic!("Principal not found: {}", name);
        }

        fn assert_count(self, count: usize) -> Self {
            assert_eq!(self.items.len(), count, "Principal count failed validation");
            assert_eq!(self.total, count, "Principal total failed validation");
            self
        }
    }

    trait ValidatePrincipal {
        fn validate<'x>(
            &self,
            typ: Type,
            items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
        );
    }

    impl ValidatePrincipal for PrincipalSet {
        fn validate<'x>(
            &self,
            typ: Type,
            items: impl IntoIterator<Item = (PrincipalField, &'x [&'x str])>,
        ) {
            assert_eq!(self.typ(), typ, "Type failed validation");

            for (field, values) in items {
                match (
                    self.get_str_array(field).filter(|v| !v.is_empty()),
                    (!values.is_empty()).then_some(values),
                ) {
                    (Some(values), Some(expected)) => {
                        assert_eq!(
                            values.iter().map(|s| s.as_str()).collect::<AHashSet<_>>(),
                            expected.iter().copied().collect::<AHashSet<_>>(),
                            "Field {field:?} failed validation: {values:?} != {expected:?}"
                        );
                    }
                    (None, None) => {}
                    (values, expected) => {
                        panic!("Field {field:?} failed validation: {values:?} != {expected:?}");
                    }
                }
            }
        }
    }

    trait ValidatePermissions {
        fn validate_permissions(
            self,
            expected_permissions: impl IntoIterator<Item = Permission>,
        ) -> Self;
        fn validate_tenant(self, tenant_id: u32, tenant_quota: u64) -> Self;
    }

    impl ValidatePermissions for Arc<AccessToken> {
        fn validate_permissions(
            self,
            expected_permissions: impl IntoIterator<Item = Permission>,
        ) -> Self {
            let expected_permissions: AHashSet<_> = expected_permissions.into_iter().collect();

            let permissions = self.permissions();
            for permission in &permissions {
                assert!(
                    expected_permissions.contains(permission),
                    "Permission {:?} failed validation",
                    permission
                );
            }
            assert_eq!(
                permissions.into_iter().collect::<AHashSet<_>>(),
                expected_permissions
            );

            for permission in Permission::all() {
                if self.has_permission(permission) {
                    assert!(
                        expected_permissions.contains(&permission),
                        "Permission {:?} failed validation",
                        permission
                    );
                }
            }
            self
        }

        fn validate_tenant(self, tenant_id: u32, tenant_quota: u64) -> Self {
            assert_eq!(
                self.tenant,
                Some(TenantInfo {
                    id: tenant_id,
                    quota: tenant_quota
                })
            );
            self
        }
    }


         */
}
