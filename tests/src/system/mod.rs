/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod authentication;
pub mod authorization;
pub mod directory;
pub mod oidc;
pub mod quota;
pub mod security;
pub mod tenant;

use crate::utils::server::TestServerBuilder;

#[tokio::test(flavor = "multi_thread")]
pub async fn system_tests() {
    let mut test = TestServerBuilder::new("system_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;

    // Create admin account
    let admin_id = test
        .create_user_account(
            "admin",
            "admin@example.org",
            "these_pretzels_are_making_me_thirsty",
            &[],
        )
        .await;
    test.account("admin")
        .assign_roles_to_account(admin_id, &["user", "system"])
        .await;

    //directory::test(&test).await;
    //authentication::test(&test).await;
    //oidc::test(&mut test).await;
    //authorization::test(&mut test).await;
    //tenant::test(&mut test).await;
    //security::test(&mut test).await;
    quota::test(&mut test).await;
}
