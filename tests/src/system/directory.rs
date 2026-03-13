/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;

pub async fn test(test: &TestServer) {
    // A principal without name should fail
    /*assert_eq!(
        store
            .create_principal(PrincipalSet::default(), None, None)
            .await,
        Err(manage::err_missing(PrincipalField::Name))
    );

    // Basic account creation
    let john_id = store
        .create_principal(
            TestPrincipal {
                name: "john".into(),
                description: Some("John Doe".into()),
                secrets: vec!["secret".into(), "$app$secret2".into()],
                ..Default::default()
            }
            .into(),
            None,
            None,
        )
        .await
        .unwrap()
        .id;

    // Two accounts with the same name should fail
    assert_eq!(
        store
            .create_principal(
                TestPrincipal {
                    name: "john".into(),
                    ..Default::default()
                }
                .into(),
                None,
                None
            )
            .await,
        Err(manage::err_exists(PrincipalField::Name, "john"))
    );

    // An account using a non-existent domain should fail
    assert_eq!(
        store
            .create_principal(
                TestPrincipal {
                    name: "jane".into(),
                    emails: vec!["jane@example.org".into()],
                    ..Default::default()
                }
                .into(),
                None,
                None
            )
            .await,
        Err(manage::not_found("example.org"))
    );

    // Create a domain name
    store
        .create_principal(
            TestPrincipal {
                name: "example.org".into(),
                typ: Type::Domain,
                ..Default::default()
            }
            .into(),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(store.is_local_domain("example.org").await.unwrap());
    assert!(!store.is_local_domain("otherdomain.org").await.unwrap());

    // Add an email address
    assert!(
        store
            .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                PrincipalUpdate::add_item(
                    PrincipalField::Emails,
                    PrincipalValue::String("john@example.org".into()),
                )
            ]))
            .await
            .is_ok()
    );
    assert_eq!(
        store.rcpt("john@example.org").await.unwrap(),
        RcptType::Mailbox
    );
    assert_eq!(
        store.email_to_id("john@example.org").await.unwrap(),
        Some(john_id)
    );

    // Using non-existent domain should fail
    assert_eq!(
        store
            .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                PrincipalUpdate::add_item(
                    PrincipalField::Emails,
                    PrincipalValue::String("john@otherdomain.org".into()),
                )
            ]))
            .await,
        Err(manage::not_found("otherdomain.org"))
    );

    // Create an account with an email address
    let jane_id = store
        .create_principal(
            TestPrincipal {
                name: "jane".into(),
                description: Some("Jane Doe".into()),
                secrets: vec!["my_secret".into(), "$app$my_secret2".into()],
                emails: vec!["jane@example.org".into()],
                quota: 123,
                ..Default::default()
            }
            .into(),
            None,
            None,
        )
        .await
        .unwrap()
        .id;

    assert_eq!(
        store.rcpt("jane@example.org").await.unwrap(),
        RcptType::Mailbox
    );
    assert_eq!(
        store.rcpt("jane@otherdomain.org").await.unwrap(),
        RcptType::Invalid
    );
    assert_eq!(
        store.email_to_id("jane@example.org").await.unwrap(),
        Some(jane_id)
    );
    assert_eq!(store.vrfy("jane").await.unwrap(), vec!["jane@example.org"]);
    assert_eq!(
        store
            .query(
                QueryParams::credentials(&Credentials::new("jane".into(), "my_secret".into()))
                    .with_return_member_of(true)
            )
            .await
            .unwrap()
            .map(|p| p.into_test()),
        Some(TestPrincipal {
            id: jane_id,
            name: "jane".into(),
            description: Some("Jane Doe".into()),
            emails: vec!["jane@example.org".into()],
            secrets: vec!["my_secret".into(), "$app$my_secret2".into()],
            quota: 123,
            ..Default::default()
        })
    );
    assert_eq!(
        store
            .query(
                QueryParams::credentials(&Credentials::new("jane".into(), "wrong_password".into()))
                    .with_return_member_of(true)
            )
            .await
            .unwrap(),
        None
    );

    // Duplicate email address should fail
    assert_eq!(
        store
            .create_principal(
                TestPrincipal {
                    name: "janeth".into(),
                    description: Some("Janeth Doe".into()),
                    emails: vec!["jane@example.org".into()],
                    ..Default::default()
                }
                .into(),
                None,
                None
            )
            .await,
        Err(manage::err_exists(
            PrincipalField::Emails,
            "jane@example.org"
        ))
    );

    // Create a mailing list
    let list_id = store
        .create_principal(
            TestPrincipal {
                name: "list".into(),
                typ: Type::List,
                emails: vec!["list@example.org".into()],
                ..Default::default()
            }
            .into(),
            None,
            None,
        )
        .await
        .unwrap()
        .id;
    assert!(
        store
            .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                PrincipalUpdate::set(
                    PrincipalField::Members,
                    PrincipalValue::StringList(vec!["john".into(), "jane".into()]),
                ),
                PrincipalUpdate::set(
                    PrincipalField::ExternalMembers,
                    PrincipalValue::StringList(vec![
                        "mike@other.org".into(),
                        "lucy@foobar.net".into()
                    ]),
                )
            ]))
            .await
            .is_ok()
    );

    assert_list_members(
        &store,
        "list@example.org",
        [
            "john@example.org",
            "mike@other.org",
            "lucy@foobar.net",
            "jane@example.org",
        ],
    )
    .await;

    assert_eq!(
        store
            .query(QueryParams::name("list").with_return_member_of(true))
            .await
            .unwrap()
            .unwrap()
            .into_test(),
        TestPrincipal {
            name: "list".into(),
            id: list_id,
            typ: Type::List,
            emails: vec!["list@example.org".into()],
            ..Default::default()
        }
    );
    assert_eq!(
        store
            .expn("list@example.org")
            .await
            .unwrap()
            .into_iter()
            .collect::<AHashSet<_>>(),
        [
            "john@example.org",
            "mike@other.org",
            "lucy@foobar.net",
            "jane@example.org"
        ]
        .into_iter()
        .map(|s| s.into())
        .collect::<AHashSet<_>>()
    );

    // Create groups
    store
        .create_principal(
            TestPrincipal {
                name: "sales".into(),
                description: Some("Sales Team".into()),
                typ: Type::Group,
                ..Default::default()
            }
            .into(),
            None,
            None,
        )
        .await
        .unwrap();
    store
        .create_principal(
            TestPrincipal {
                name: "support".into(),
                description: Some("Support Team".into()),
                typ: Type::Group,
                ..Default::default()
            }
            .into(),
            None,
            None,
        )
        .await
        .unwrap();

    // Add John to the Sales and Support groups
    assert!(
        store
            .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                PrincipalUpdate::add_item(
                    PrincipalField::MemberOf,
                    PrincipalValue::String("sales".into()),
                ),
                PrincipalUpdate::add_item(
                    PrincipalField::MemberOf,
                    PrincipalValue::String("support".into()),
                )
            ]))
            .await
            .is_ok()
    );
    let principal = store
        .query(QueryParams::name("john").with_return_member_of(true))
        .await
        .unwrap()
        .unwrap();
    let principal = store.map_principal(principal, &[]).await.unwrap();
    assert_eq!(
        principal.into_test().into_sorted(),
        TestPrincipal {
            id: john_id,
            name: "john".into(),
            description: Some("John Doe".into()),
            secrets: vec!["secret".into(), "$app$secret2".into()],
            emails: vec!["john@example.org".into()],
            member_of: vec!["sales".into(), "support".into()],
            lists: vec!["list".into()],
            ..Default::default()
        }
    );

    // Adding a non-existent user should fail
    assert_eq!(
        store
            .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                PrincipalUpdate::add_item(
                    PrincipalField::MemberOf,
                    PrincipalValue::String("accounting".into()),
                )
            ]))
            .await,
        Err(manage::not_found("accounting"))
    );

    // Remove a member from a group
    assert!(
        store
            .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                PrincipalUpdate::remove_item(
                    PrincipalField::MemberOf,
                    PrincipalValue::String("support".into()),
                )
            ]))
            .await
            .is_ok()
    );
    let principal = store
        .query(QueryParams::name("john").with_return_member_of(true))
        .await
        .unwrap()
        .unwrap();
    let principal = store.map_principal(principal, &[]).await.unwrap();
    assert_eq!(
        principal.into_test().into_sorted(),
        TestPrincipal {
            id: john_id,
            name: "john".into(),
            description: Some("John Doe".into()),
            secrets: vec!["secret".into(), "$app$secret2".into()],
            emails: vec!["john@example.org".into()],
            member_of: vec!["sales".into()],
            lists: vec!["list".into()],
            ..Default::default()
        }
    );

    // Update multiple fields
    assert!(
        store
            .update_principal(UpdatePrincipal::by_name("john").with_updates(vec![
                PrincipalUpdate::set(
                    PrincipalField::Name,
                    PrincipalValue::String("john.doe".into())
                ),
                PrincipalUpdate::set(
                    PrincipalField::Description,
                    PrincipalValue::String("Johnny Doe".into())
                ),
                PrincipalUpdate::set(
                    PrincipalField::Secrets,
                    PrincipalValue::StringList(vec!["12345".into()])
                ),
                PrincipalUpdate::set(PrincipalField::Quota, PrincipalValue::Integer(1024)),
                PrincipalUpdate::remove_item(
                    PrincipalField::Emails,
                    PrincipalValue::String("john@example.org".into()),
                ),
                PrincipalUpdate::add_item(
                    PrincipalField::Emails,
                    PrincipalValue::String("john.doe@example.org".into()),
                )
            ]))
            .await
            .is_ok()
    );

    let principal = store
        .query(QueryParams::name("john.doe").with_return_member_of(true))
        .await
        .unwrap()
        .unwrap();
    let principal = store.map_principal(principal, &[]).await.unwrap();
    assert_eq!(
        principal.into_test().into_sorted(),
        TestPrincipal {
            id: john_id,
            name: "john.doe".into(),
            description: Some("Johnny Doe".into()),
            secrets: vec!["12345".into()],
            emails: vec!["john.doe@example.org".into()],
            quota: 1024,
            typ: Type::Individual,
            member_of: vec!["sales".into()],
            lists: vec!["list".into()],
            ..Default::default()
        }
    );
    assert_eq!(store.get_principal_id("john").await.unwrap(), None);
    assert_eq!(
        store.rcpt("john@example.org").await.unwrap(),
        RcptType::Invalid
    );
    assert_eq!(
        store.rcpt("john.doe@example.org").await.unwrap(),
        RcptType::Mailbox
    );

    // Remove a member from a mailing list and then add it back
    assert!(
        store
            .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                PrincipalUpdate::remove_item(
                    PrincipalField::Members,
                    PrincipalValue::String("john.doe".into()),
                )
            ]))
            .await
            .is_ok()
    );
    assert_list_members(
        &store,
        "list@example.org",
        ["jane@example.org", "mike@other.org", "lucy@foobar.net"],
    )
    .await;
    assert!(
        store
            .update_principal(UpdatePrincipal::by_name("list").with_updates(vec![
                PrincipalUpdate::add_item(
                    PrincipalField::Members,
                    PrincipalValue::String("john.doe".into()),
                )
            ]))
            .await
            .is_ok()
    );
    assert_list_members(
        &store,
        "list@example.org",
        [
            "john.doe@example.org",
            "jane@example.org",
            "mike@other.org",
            "lucy@foobar.net",
        ],
    )
    .await;

    // Field validation
    assert_eq!(
        store
            .update_principal(UpdatePrincipal::by_name("john.doe").with_updates(vec![
                PrincipalUpdate::set(PrincipalField::Name, PrincipalValue::String("jane".into())),
            ]))
            .await,
        Err(manage::err_exists(PrincipalField::Name, "jane"))
    );
    assert_eq!(
        store
            .update_principal(UpdatePrincipal::by_name("john.doe").with_updates(vec![
                PrincipalUpdate::add_item(
                    PrincipalField::Emails,
                    PrincipalValue::String("jane@example.org".into())
                ),
            ]))
            .await,
        Err(manage::err_exists(
            PrincipalField::Emails,
            "jane@example.org"
        ))
    );

    // List accounts
    assert_eq!(
        store
            .list_principals(
                None,
                None,
                &[Type::Individual, Type::Group, Type::List],
                true,
                0,
                0
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<AHashSet<_>>(),
        ["jane", "john.doe", "list", "sales", "support"]
            .into_iter()
            .map(|s| s.into())
            .collect::<AHashSet<_>>()
    );
    assert_eq!(
        store
            .list_principals("john".into(), None, &[], true, 0, 0)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<Vec<_>>(),
        vec!["john.doe"]
    );
    assert_eq!(
        store
            .list_principals(None, None, &[Type::Individual], true, 0, 0)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<AHashSet<_>>(),
        ["jane", "john.doe"]
            .into_iter()
            .map(|s| s.into())
            .collect::<AHashSet<_>>()
    );
    assert_eq!(
        store
            .list_principals(None, None, &[Type::Group], true, 0, 0)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<AHashSet<_>>(),
        ["sales", "support"]
            .into_iter()
            .map(|s| s.into())
            .collect::<AHashSet<_>>()
    );
    assert_eq!(
        store
            .list_principals(None, None, &[Type::List], true, 0, 0)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<Vec<_>>(),
        vec!["list"]
    );
    assert_eq!(
        store
            .list_principals("example.org".into(), None, &[], true, 0, 0)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<Vec<_>>(),
        vec!["example.org", "jane", "john.doe", "list"]
    );
    assert_eq!(
        store
            .list_principals("johnny doe".into(), None, &[], true, 0, 0)
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<Vec<_>>(),
        vec!["john.doe"]
    );

    // Write records on John's and Jane's accounts
    let mut document_id = u32::MAX;
    for account_id in [john_id, jane_id] {
        document_id = store
            .assign_document_ids(u32::MAX, Collection::Principal, 1)
            .await
            .unwrap();
        store
            .write(
                BatchBuilder::new()
                    .with_account_id(account_id)
                    .with_collection(Collection::Email)
                    .with_document(document_id)
                    .set(ValueClass::Property(0), "hello".as_bytes())
                    .build_all(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .get_value::<String>(ValueKey {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                    class: ValueClass::Property(0)
                })
                .await
                .unwrap(),
            Some("hello".into())
        );
    }

    // Delete John's account and make sure his records are gone
    let server = Server {
        inner: Arc::new(Inner::default()),
        core: Arc::new(Core {
            storage: Storage {
                data: store.clone(),
                blob: store.clone().into(),
                fts: store.clone().into(),
                ..Default::default()
            },
            ..Default::default()
        }),
    };
    store.delete_principal(QueryBy::Id(john_id)).await.unwrap();
    destroy_account_data(&server, john_id, true).await.unwrap();
    assert_eq!(store.get_principal_id("john.doe").await.unwrap(), None);
    assert_eq!(
        store.email_to_id("john.doe@example.org").await.unwrap(),
        None
    );
    assert_eq!(
        store.rcpt("john.doe@example.org").await.unwrap(),
        RcptType::Invalid
    );
    assert_eq!(
        store
            .list_principals(
                None,
                None,
                &[Type::Individual, Type::Group, Type::List],
                true,
                0,
                0
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|p| p.name)
            .collect::<AHashSet<_>>(),
        ["jane", "list", "sales", "support"]
            .into_iter()
            .map(|s| s.into())
            .collect::<AHashSet<_>>()
    );
    assert!(!account_has_emails(&store, john_id).await);
    assert_eq!(
        store
            .get_value::<String>(ValueKey {
                account_id: john_id,
                collection: Collection::Email.into(),
                document_id: 0,
                class: ValueClass::Property(0)
            })
            .await
            .unwrap(),
        None
    );

    // Make sure Jane's records are still there
    assert_eq!(store.get_principal_id("jane").await.unwrap(), Some(jane_id));
    assert_eq!(
        store.email_to_id("jane@example.org").await.unwrap(),
        Some(jane_id)
    );
    assert_eq!(
        store.rcpt("jane@example.org").await.unwrap(),
        RcptType::Mailbox
    );
    assert!(account_has_emails(&store, jane_id).await);
    assert_eq!(
        store
            .get_value::<String>(ValueKey {
                account_id: jane_id,
                collection: Collection::Email.into(),
                document_id,
                class: ValueClass::Property(0)
            })
            .await
            .unwrap(),
        Some("hello".into())
    );

    // Clean up
    destroy_account_data(&server, jane_id, true).await.unwrap();
    for principal_name in ["jane", "list", "sales", "support", "example.org"] {
        store
            .delete_principal(QueryBy::Name(principal_name))
            .await
            .unwrap();
    }
    store_assert_is_empty(&store, store.clone().into(), true).await;*/
}
