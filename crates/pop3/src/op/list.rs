/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use common::listener::SessionStream;

use crate::{protocol::response::Response, Session};

impl<T: SessionStream> Session<T> {
    pub async fn handle_list(&mut self, msg: Option<u32>) -> Result<(), ()> {
        let mailbox = self.state.mailbox();
        if let Some(msg) = msg {
            if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
                self.write_ok(format!("{} {}", msg, message.size)).await
            } else {
                self.write_err("No such message").await
            }
        } else {
            self.write_bytes(
                Response::List(mailbox.messages.iter().map(|m| m.size).collect::<Vec<_>>())
                    .serialize(),
            )
            .await
        }
    }

    pub async fn handle_uidl(&mut self, msg: Option<u32>) -> Result<(), ()> {
        let mailbox = self.state.mailbox();
        if let Some(msg) = msg {
            if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
                self.write_ok(format!("{} {}{}", msg, mailbox.uid_validity, message.uid))
                    .await
            } else {
                self.write_err("No such message").await
            }
        } else {
            self.write_bytes(
                Response::List(
                    mailbox
                        .messages
                        .iter()
                        .map(|m| format!("{}{}", mailbox.uid_validity, m.uid))
                        .collect::<Vec<_>>(),
                )
                .serialize(),
            )
            .await
        }
    }

    pub async fn handle_stat(&mut self) -> Result<(), ()> {
        let mailbox = self.state.mailbox();
        self.write_ok(format!("{} {}", mailbox.total, mailbox.size))
            .await
    }
}
