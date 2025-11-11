/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Session;
use common::listener::SessionStream;
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::INBOX_ID,
};
use std::collections::BTreeMap;
use store::{
    IterateParams, U32_LEN, ValueKey,
    ahash::AHashMap,
    write::{IndexPropertyClass, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField, special_use::SpecialUse};

#[derive(Default)]
pub struct Mailbox {
    pub messages: Vec<Message>,
    pub account_id: u32,
    pub uid_validity: u32,
    pub total: u32,
    pub size: u32,
}

pub struct Message {
    pub id: u32,
    pub uid: u32,
    pub size: u32,
    pub deleted: bool,
}

impl<T: SessionStream> Session<T> {
    pub async fn fetch_mailbox(&self, account_id: u32) -> trc::Result<Mailbox> {
        // Obtain UID validity
        let cache = self
            .server
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;

        if cache.emails.items.is_empty() {
            return Ok(Mailbox::default());
        }

        let uid_validity = cache
            .mailbox_by_role(&SpecialUse::Inbox)
            .map(|x| x.uid_validity)
            .unwrap_or_default();

        // Obtain message sizes
        let mut message_sizes = AHashMap::new();
        self.server
            .store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: EmailField::ReceivedToSize.into(),
                            value: 0,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                            property: EmailField::ReceivedToSize.into(),
                            value: u64::MAX,
                        }),
                    },
                )
                .ascending(),
                |key, value| {
                    message_sizes.insert(
                        key.deserialize_be_u32(key.len() - U32_LEN)?,
                        value.deserialize_be_u32(0)?,
                    );

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        // Sort by UID
        let message_map = cache
            .emails
            .items
            .iter()
            .filter_map(|message| {
                message
                    .mailboxes
                    .iter()
                    .find(|m| m.mailbox_id == INBOX_ID)
                    .map(|m| (m.uid, message.document_id))
            })
            .collect::<BTreeMap<u32, u32>>();

        // Create mailbox
        let mut mailbox = Mailbox {
            messages: Vec::with_capacity(message_map.len()),
            uid_validity,
            account_id,
            ..Default::default()
        };
        for (uid, id) in message_map {
            if let Some(size) = message_sizes.get(&id) {
                mailbox.messages.push(Message {
                    id,
                    uid,
                    size: *size,
                    deleted: false,
                });
                mailbox.total += 1;
                mailbox.size += *size;
            }
        }

        Ok(mailbox)
    }
}
