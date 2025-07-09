/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::queue::{QueueExpiry, QueueName};
use smtp::queue::{Recipient, Schedule, Status};

pub mod concurrent;
pub mod dsn;
pub mod manager;
pub mod retry;

pub fn build_rcpt(address: &str, retry: u64, notify: u64, expires: u64) -> Recipient {
    Recipient {
        address: address.to_string(),
        address_lcase: address.to_string(),
        retry: Schedule::later(retry),
        notify: Schedule::later(notify),
        expires: QueueExpiry::Duration(expires),
        status: Status::Scheduled,
        flags: 0,
        orcpt: None,
        queue: QueueName::default(),
    }
}
