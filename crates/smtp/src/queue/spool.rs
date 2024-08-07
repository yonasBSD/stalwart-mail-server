/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::DomainPart;
use std::borrow::Cow;
use std::time::{Duration, SystemTime};
use store::write::key::DeserializeBigEndian;
use store::write::{now, BatchBuilder, Bincode, BlobOp, QueueClass, QueueEvent, ValueClass};
use store::{Deserialize, IterateParams, Serialize, ValueKey, U64_LEN};
use trc::ServerEvent;
use utils::BlobHash;

use crate::core::SMTP;

use super::{
    Domain, Event, Message, MessageSource, QueueEnvelope, QueueId, QuotaKey, Recipient, Schedule,
    Status,
};

pub const LOCK_EXPIRY: u64 = 300;

#[derive(Debug)]
pub struct QueueEventLock {
    pub due: u64,
    pub queue_id: u64,
    pub lock_expiry: u64,
}

impl SMTP {
    pub fn new_message(
        &self,
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
        span_id: u64,
    ) -> Message {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Message {
            queue_id: self.inner.queue_id_gen.generate().unwrap_or(created),
            span_id,
            created,
            return_path: return_path.into(),
            return_path_lcase: return_path_lcase.into(),
            return_path_domain: return_path_domain.into(),
            recipients: Vec::with_capacity(1),
            domains: Vec::with_capacity(1),
            flags: 0,
            env_id: None,
            priority: 0,
            size: 0,
            blob_hash: Default::default(),
            quota_keys: Vec::new(),
        }
    }

    pub async fn next_event(&self) -> Vec<QueueEventLock> {
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
            due: 0,
            queue_id: 0,
        })));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
            due: u64::MAX,
            queue_id: u64::MAX,
        })));

        let mut events = Vec::new();
        let now = now();
        let result = self
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let event = QueueEventLock {
                        due: key.deserialize_be_u64(0)?,
                        queue_id: key.deserialize_be_u64(U64_LEN)?,
                        lock_expiry: u64::deserialize(value)?,
                    };
                    let do_continue = event.due <= now;
                    if event.lock_expiry < now {
                        events.push(event);
                    } else {
                        trc::event!(
                            Queue(trc::QueueEvent::Locked),
                            SpanId = event.queue_id,
                            Due = trc::Value::Timestamp(event.due),
                            Expires = trc::Value::Timestamp(event.lock_expiry),
                        );
                    }
                    Ok(do_continue)
                },
            )
            .await;

        if let Err(err) = result {
            trc::error!(err
                .details("Failed to read queue.")
                .caused_by(trc::location!()));
        }

        events
    }

    pub async fn try_lock_event(&self, mut event: QueueEventLock) -> Option<QueueEventLock> {
        let mut batch = BatchBuilder::new();
        batch.assert_value(
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: event.due,
                queue_id: event.queue_id,
            })),
            event.lock_expiry,
        );
        event.lock_expiry = now() + LOCK_EXPIRY;
        batch.set(
            ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: event.due,
                queue_id: event.queue_id,
            })),
            event.lock_expiry.serialize(),
        );
        match self.core.storage.data.write(batch.build()).await {
            Ok(_) => Some(event),
            Err(err) if err.is_assertion_failure() => {
                trc::event!(
                    Queue(trc::QueueEvent::LockBusy),
                    SpanId = event.queue_id,
                    Due = trc::Value::Timestamp(event.due),
                    CausedBy = err,
                );

                None
            }
            Err(err) => {
                trc::error!(err
                    .details("Failed to lock event.")
                    .caused_by(trc::location!()));
                None
            }
        }
    }

    pub async fn read_message(&self, id: QueueId) -> Option<Message> {
        match self
            .core
            .storage
            .data
            .get_value::<Bincode<Message>>(ValueKey::from(ValueClass::Queue(QueueClass::Message(
                id,
            ))))
            .await
        {
            Ok(Some(message)) => Some(message.inner),
            Ok(None) => None,
            Err(err) => {
                trc::error!(err
                    .details("Failed to read message.")
                    .caused_by(trc::location!()));

                None
            }
        }
    }
}

impl Message {
    pub async fn queue(
        mut self,
        raw_headers: Option<&[u8]>,
        raw_message: &[u8],
        session_id: u64,
        core: &SMTP,
        source: MessageSource,
    ) -> bool {
        // Write blob
        let message = if let Some(raw_headers) = raw_headers {
            let mut message = Vec::with_capacity(raw_headers.len() + raw_message.len());
            message.extend_from_slice(raw_headers);
            message.extend_from_slice(raw_message);
            Cow::Owned(message)
        } else {
            raw_message.into()
        };
        self.blob_hash = BlobHash::from(message.as_ref());

        // Generate id
        if self.size == 0 {
            self.size = message.len();
        }

        // Reserve and write blob
        let mut batch = BatchBuilder::new();
        let reserve_until = now() + 120;
        batch.set(
            BlobOp::Reserve {
                hash: self.blob_hash.clone(),
                until: reserve_until,
            },
            0u32.serialize(),
        );
        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            trc::error!(err
                .details("Failed to write to store.")
                .span_id(session_id)
                .caused_by(trc::location!()));

            return false;
        }
        if let Err(err) = core
            .core
            .storage
            .blob
            .put_blob(self.blob_hash.as_slice(), message.as_ref())
            .await
        {
            trc::error!(err
                .details("Failed to write blob.")
                .span_id(session_id)
                .caused_by(trc::location!()));

            return false;
        }

        trc::event!(
            Queue(match source {
                MessageSource::Authenticated => trc::QueueEvent::QueueMessageSubmission,
                MessageSource::Unauthenticated => trc::QueueEvent::QueueMessage,
                MessageSource::Dsn => trc::QueueEvent::QueueDsn,
                MessageSource::Report => trc::QueueEvent::QueueReport,
                MessageSource::Sieve => trc::QueueEvent::QueueAutogenerated,
            }),
            SpanId = session_id,
            QueueId = self.queue_id,
            From = if !self.return_path.is_empty() {
                trc::Value::String(self.return_path.to_string())
            } else {
                trc::Value::Static("<>")
            },
            To = self
                .recipients
                .iter()
                .map(|r| trc::Value::String(r.address_lcase.clone()))
                .collect::<Vec<_>>(),
            Size = self.size,
            NextRetry = trc::Value::Timestamp(self.next_delivery_event()),
            NextDsn = trc::Value::Timestamp(self.next_dsn()),
            Expires = trc::Value::Timestamp(self.expires()),
        );

        // Write message to queue
        let mut batch = BatchBuilder::new();

        // Reserve quotas
        for quota_key in &self.quota_keys {
            match quota_key {
                QuotaKey::Count { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount(key.clone())), 1);
                }
                QuotaKey::Size { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize(key.clone())),
                        self.size as i64,
                    );
                }
            }
        }
        batch
            .set(
                ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                    due: self.next_event().unwrap_or_default(),
                    queue_id: self.queue_id,
                })),
                0u64.serialize(),
            )
            .clear(BlobOp::Reserve {
                hash: self.blob_hash.clone(),
                until: reserve_until,
            })
            .set(
                BlobOp::LinkId {
                    hash: self.blob_hash.clone(),
                    id: self.queue_id,
                },
                vec![],
            )
            .set(
                BlobOp::Commit {
                    hash: self.blob_hash.clone(),
                },
                vec![],
            )
            .set(
                ValueClass::Queue(QueueClass::Message(self.queue_id)),
                Bincode::new(self).serialize(),
            );

        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            trc::error!(err
                .details("Failed to write to store.")
                .span_id(session_id)
                .caused_by(trc::location!()));

            return false;
        }

        // Queue the message
        if core.inner.queue_tx.send(Event::Reload).await.is_err() {
            trc::event!(
                Server(ServerEvent::ThreadError),
                Reason = "Channel closed.",
                CausedBy = trc::location!(),
                SpanId = session_id,
            );
        }

        true
    }

    pub async fn add_recipient_parts(
        &mut self,
        rcpt: impl Into<String>,
        rcpt_lcase: impl Into<String>,
        rcpt_domain: impl Into<String>,
        core: &SMTP,
    ) {
        let rcpt_domain = rcpt_domain.into();
        let domain_idx =
            if let Some(idx) = self.domains.iter().position(|d| d.domain == rcpt_domain) {
                idx
            } else {
                let idx = self.domains.len();

                self.domains.push(Domain {
                    domain: rcpt_domain,
                    retry: Schedule::now(),
                    notify: Schedule::now(),
                    expires: 0,
                    status: Status::Scheduled,
                });

                let expires = core
                    .core
                    .eval_if(
                        &core.core.smtp.queue.expire,
                        &QueueEnvelope::new(self, idx),
                        self.span_id,
                    )
                    .await
                    .unwrap_or_else(|| Duration::from_secs(5 * 86400));

                // Update expiration
                let domain = self.domains.last_mut().unwrap();
                domain.notify = Schedule::later(expires + Duration::from_secs(10));
                domain.expires = now() + expires.as_secs();

                idx
            };
        self.recipients.push(Recipient {
            domain_idx,
            address: rcpt.into(),
            address_lcase: rcpt_lcase.into(),
            status: Status::Scheduled,
            flags: 0,
            orcpt: None,
        });
    }

    pub async fn add_recipient(&mut self, rcpt: impl Into<String>, core: &SMTP) {
        let rcpt = rcpt.into();
        let rcpt_lcase = rcpt.to_lowercase();
        let rcpt_domain = rcpt_lcase.domain_part().to_string();
        self.add_recipient_parts(rcpt, rcpt_lcase, rcpt_domain, core)
            .await;
    }

    pub async fn save_changes(
        mut self,
        core: &SMTP,
        prev_event: Option<u64>,
        next_event: Option<u64>,
    ) -> bool {
        debug_assert!(prev_event.is_some() == next_event.is_some());

        let mut batch = BatchBuilder::new();

        // Release quota for completed deliveries
        self.release_quota(&mut batch);

        // Update message queue
        let mut batch = BatchBuilder::new();
        if let (Some(prev_event), Some(next_event)) = (prev_event, next_event) {
            batch
                .clear(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                    due: prev_event,
                    queue_id: self.queue_id,
                })))
                .set(
                    ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                        due: next_event,
                        queue_id: self.queue_id,
                    })),
                    0u64.serialize(),
                );
        }

        let span_id = self.span_id;
        batch.set(
            ValueClass::Queue(QueueClass::Message(self.queue_id)),
            Bincode::new(self).serialize(),
        );

        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            trc::error!(err
                .details("Failed to save changes.")
                .span_id(span_id)
                .caused_by(trc::location!()));
            false
        } else {
            true
        }
    }

    pub async fn remove(self, core: &SMTP, prev_event: u64) -> bool {
        let mut batch = BatchBuilder::new();

        // Release all quotas
        for quota_key in self.quota_keys {
            match quota_key {
                QuotaKey::Count { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount(key)), -1);
                }
                QuotaKey::Size { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize(key)),
                        -(self.size as i64),
                    );
                }
            }
        }

        batch
            .clear(BlobOp::LinkId {
                hash: self.blob_hash.clone(),
                id: self.queue_id,
            })
            .clear(ValueClass::Queue(QueueClass::MessageEvent(QueueEvent {
                due: prev_event,
                queue_id: self.queue_id,
            })))
            .clear(ValueClass::Queue(QueueClass::Message(self.queue_id)));

        if let Err(err) = core.core.storage.data.write(batch.build()).await {
            trc::error!(err
                .details("Failed to write to update queue.")
                .span_id(self.span_id)
                .caused_by(trc::location!()));
            false
        } else {
            true
        }
    }
}
