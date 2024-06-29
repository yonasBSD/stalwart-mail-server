/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use jmap_proto::types::{state::StateChange, type_state::DataType};
use store::roaring::RoaringBitmap;

use crate::{Session, State};

impl<T: SessionStream> Session<T> {
    pub async fn handle_dele(&mut self, msgs: Vec<u32>) -> Result<(), ()> {
        let mailbox = self.state.mailbox_mut();
        let mut response = Vec::new();

        for msg in msgs {
            if let Some(message) = mailbox.messages.get_mut(msg.saturating_sub(1) as usize) {
                if !message.deleted {
                    response.extend_from_slice(format!("+OK message {msg} deleted\r\n").as_bytes());
                    message.deleted = true;
                } else {
                    response.extend_from_slice(
                        format!("-ERR message {msg} already deleted\r\n").as_bytes(),
                    );
                }
            } else {
                response.extend_from_slice("-ERR no such message\r\n".as_bytes());
            }
        }

        self.write_bytes(response).await
    }

    pub async fn handle_rset(&mut self) -> Result<(), ()> {
        let mut count = 0;
        let mailbox = self.state.mailbox_mut();
        for message in &mut mailbox.messages {
            if message.deleted {
                count += 1;
                message.deleted = false;
            }
        }
        self.write_ok(format!("{count} messages undeleted")).await
    }

    pub async fn handle_quit(&mut self) -> Result<(), ()> {
        if let State::Authenticated { mailbox, .. } = &self.state {
            let mut deleted = RoaringBitmap::new();
            for message in &mailbox.messages {
                if message.deleted {
                    deleted.insert(message.id);
                }
            }

            if !deleted.is_empty() {
                let num_deleted = deleted.len();
                match self
                    .jmap
                    .emails_tombstone(mailbox.account_id, deleted)
                    .await
                {
                    Ok((changes, not_deleted)) => {
                        if !changes.is_empty() {
                            if let Ok(change_id) =
                                self.jmap.commit_changes(mailbox.account_id, changes).await
                            {
                                self.jmap
                                    .broadcast_state_change(
                                        StateChange::new(mailbox.account_id)
                                            .with_change(DataType::Email, change_id)
                                            .with_change(DataType::Mailbox, change_id)
                                            .with_change(DataType::Thread, change_id),
                                    )
                                    .await;
                            }
                        }
                        if not_deleted.is_empty() {
                            self.write_ok(format!(
                                "Stalwart POP3 bids you farewell ({num_deleted} messages deleted)."
                            ))
                            .await?;
                        } else {
                            self.write_err("Some messages could not be deleted").await?;
                        }
                    }
                    Err(_) => {
                        self.write_err("Failed to delete messages").await?;
                    }
                }
            } else {
                self.write_ok("Stalwart POP3 bids you farewell (no messages deleted).")
                    .await?;
            }
        } else {
            self.write_ok("Stalwart POP3 bids you farewell.").await?;
        }

        Err(())
    }
}
