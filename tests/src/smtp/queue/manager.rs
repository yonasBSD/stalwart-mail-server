/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::smtp::{TestSMTP, queue::build_rcpt};
use common::config::smtp::queue::QueueName;
use smtp::queue::{
    Error, ErrorDetails, Message, MessageWrapper, Recipient, Status, spool::SmtpSpool,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use store::write::now;

const CONFIG: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true
"#;

#[tokio::test]
async fn queue_due() {
    // Enable logging
    crate::enable_logging();

    let local = TestSMTP::new("smtp_queue_due_test", CONFIG).await;
    let core = local.build_smtp();
    let qr = &local.queue_receiver;

    let mut message = new_message(0);
    message.message.recipients.push(build_rcpt("c", 3, 8, 9));
    message.save_changes(&core, 0.into()).await;

    let mut message = new_message(1);
    message.message.recipients.push(build_rcpt("b", 2, 6, 7));
    message.save_changes(&core, 0.into()).await;

    let mut message = new_message(2);
    message.message.recipients.push(build_rcpt("a", 1, 4, 5));
    message.save_changes(&core, 0.into()).await;

    for domain in vec!["a", "b", "c"].into_iter() {
        let now = now();
        for queue_event in core.next_event().await {
            if queue_event.due > now {
                let wake_up = queue_event.due - now;
                assert_eq!(wake_up, 1);
                std::thread::sleep(Duration::from_secs(wake_up));
            }
            if let Some(message) = core
                .read_message(queue_event.queue_id, QueueName::default())
                .await
            {
                message.message.rcpt(domain);
                message.remove(&core, queue_event.due.into()).await;
            } else {
                panic!("Message not found");
            }
        }
    }

    qr.assert_queue_is_empty().await;
}

#[test]
fn delivery_events() {
    let mut message = new_message(0).message;
    message.created = now();

    message.recipients.push(build_rcpt("a", 1, 2, 3));
    message.recipients.push(build_rcpt("b", 4, 5, 6));
    message.recipients.push(build_rcpt("c", 7, 8, 9));

    for t in 0..2 {
        assert_eq!(
            message.next_event(None).unwrap(),
            message.rcpt("a").retry.due
        );
        assert_eq!(
            message.next_delivery_event(None).unwrap(),
            message.rcpt("a").retry.due
        );
        assert_eq!(
            message
                .next_event_after(
                    None,
                    message.rcpt("a").expiration_time(message.created).unwrap()
                )
                .unwrap(),
            message.rcpt("b").retry.due
        );
        assert_eq!(
            message
                .next_event_after(
                    None,
                    message.rcpt("b").expiration_time(message.created).unwrap()
                )
                .unwrap(),
            message.rcpt("c").retry.due
        );
        assert_eq!(
            message
                .next_event_after(None, message.rcpt("c").notify.due)
                .unwrap(),
            message.rcpt("c").expiration_time(message.created).unwrap()
        );
        assert!(
            message
                .next_event_after(
                    None,
                    message.rcpt("c").expiration_time(message.created).unwrap()
                )
                .is_none()
        );

        if t == 0 {
            message.recipients.reverse();
        } else {
            message.recipients.swap(0, 1);
        }
    }

    message.rcpt_mut("a").status = Status::PermanentFailure(ErrorDetails {
        entity: "localhost".into(),
        details: Error::ConcurrencyLimited,
    });
    assert_eq!(
        message.next_event(None).unwrap(),
        message.rcpt("b").retry.due
    );
    assert_eq!(
        message.next_delivery_event(None).unwrap(),
        message.rcpt("b").retry.due
    );

    message.rcpt_mut("b").status = Status::PermanentFailure(ErrorDetails {
        entity: "localhost".into(),
        details: Error::ConcurrencyLimited,
    });
    assert_eq!(
        message.next_event(None).unwrap(),
        message.rcpt("c").retry.due
    );
    assert_eq!(
        message.next_delivery_event(None).unwrap(),
        message.rcpt("c").retry.due
    );

    message.rcpt_mut("c").status = Status::PermanentFailure(ErrorDetails {
        entity: "localhost".into(),
        details: Error::ConcurrencyLimited,
    });
    assert!(message.next_event(None).is_none());
}

pub fn new_message(queue_id: u64) -> MessageWrapper {
    MessageWrapper {
        queue_id,
        span_id: 0,
        queue_name: QueueName::default(),
        message: Message {
            size: 0,
            created: now(),
            return_path: "sender@foobar.org".into(),
            return_path_lcase: "".into(),
            return_path_domain: "foobar.org".into(),
            recipients: vec![],
            flags: 0,
            env_id: None,
            priority: 0,
            quota_keys: vec![],
            blob_hash: Default::default(),
            received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_via_port: 0,
        },
    }
}

pub trait TestMessage {
    fn rcpt(&self, name: &str) -> &Recipient;
    fn rcpt_mut(&mut self, name: &str) -> &mut Recipient;
}

impl TestMessage for Message {
    fn rcpt(&self, name: &str) -> &Recipient {
        self.recipients
            .iter()
            .find(|d| d.address_lcase == name)
            .unwrap_or_else(|| panic!("Expected rcpt {name} not found in {:?}", self.recipients))
    }

    fn rcpt_mut(&mut self, name: &str) -> &mut Recipient {
        self.recipients
            .iter_mut()
            .find(|d| d.address_lcase == name)
            .unwrap()
    }
}
