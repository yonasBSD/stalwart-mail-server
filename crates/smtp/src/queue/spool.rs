/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedMessage, ArchivedStatus, Message, MessageSource, QueueEnvelope, QueueId, QueuedMessage,
    QuotaKey, Recipient, Schedule, Status,
};
use crate::queue::{DomainPart, MessageWrapper};
use common::config::smtp::queue::{QueueExpiry, QueueName};
use common::ipc::QueueEvent;
use common::{KV_LOCK_QUEUE_MESSAGE, Server};
use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;
use store::write::key::DeserializeBigEndian;
use store::write::{
    AlignedBytes, Archive, Archiver, BatchBuilder, BlobOp, QueueClass, ValueClass, now,
};
use store::{IterateParams, Serialize, SerializeInfallible, U64_LEN, ValueKey};
use trc::ServerEvent;
use utils::BlobHash;

pub const LOCK_EXPIRY: u64 = 300;
pub const QUEUE_REFRESH: u64 = 300;

pub trait SmtpSpool: Sync + Send {
    fn new_message(
        &self,
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
        span_id: u64,
    ) -> MessageWrapper;

    fn next_event(&self) -> impl Future<Output = Vec<QueuedMessage>> + Send;

    fn try_lock_event(&self, queue_id: QueueId) -> impl Future<Output = bool> + Send;

    fn unlock_event(&self, queue_id: QueueId) -> impl Future<Output = ()> + Send;

    fn read_message(
        &self,
        id: QueueId,
        queue_name: QueueName,
    ) -> impl Future<Output = Option<MessageWrapper>> + Send;

    fn read_message_archive(
        &self,
        id: QueueId,
    ) -> impl Future<Output = trc::Result<Option<Archive<AlignedBytes>>>> + Send;
}

impl SmtpSpool for Server {
    fn new_message(
        &self,
        return_path: impl Into<String>,
        return_path_lcase: impl Into<String>,
        return_path_domain: impl Into<String>,
        span_id: u64,
    ) -> MessageWrapper {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        MessageWrapper {
            queue_id: self.inner.data.queue_id_gen.generate(),
            queue_name: QueueName::default(),
            span_id,
            message: Message {
                created,
                return_path: return_path.into(),
                return_path_lcase: return_path_lcase.into(),
                return_path_domain: return_path_domain.into(),
                recipients: Vec::with_capacity(1),
                flags: 0,
                env_id: None,
                priority: 0,
                size: 0,
                blob_hash: Default::default(),
                quota_keys: Vec::new(),
                received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                received_via_port: 0,
            },
        }
    }

    async fn next_event(&self) -> Vec<QueuedMessage> {
        let now = now();
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: 0,
                queue_id: 0,
                queue_name: [0; 8],
            },
        )));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: now + QUEUE_REFRESH,
                queue_id: u64::MAX,
                queue_name: [u8::MAX; 8],
            },
        )));

        let mut events = Vec::new();

        let result = self
            .store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let due = key.deserialize_be_u64(0)?;
                    let queue_id = key.deserialize_be_u64(U64_LEN)?;
                    let queue_name =
                        QueueName::from_bytes(key.get(U64_LEN + U64_LEN..).unwrap_or_default())
                            .unwrap_or_default();

                    events.push(QueuedMessage {
                        due,
                        queue_id,
                        queue_name,
                    });

                    Ok(due <= now)
                },
            )
            .await;

        if let Err(err) = result {
            trc::error!(
                err.details("Failed to read queue.")
                    .caused_by(trc::location!())
            );
        }

        events
    }

    async fn try_lock_event(&self, queue_id: QueueId) -> bool {
        match self
            .in_memory_store()
            .try_lock(KV_LOCK_QUEUE_MESSAGE, &queue_id.to_be_bytes(), LOCK_EXPIRY)
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(Queue(trc::QueueEvent::Locked), QueueId = queue_id,);
                }
                result
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock event.")
                        .caused_by(trc::location!())
                );
                false
            }
        }
    }

    async fn unlock_event(&self, queue_id: QueueId) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_QUEUE_MESSAGE, &queue_id.to_be_bytes())
            .await
        {
            trc::error!(
                err.details("Failed to unlock event.")
                    .caused_by(trc::location!())
            );
        }
    }

    async fn read_message(
        &self,
        queue_id: QueueId,
        queue_name: QueueName,
    ) -> Option<MessageWrapper> {
        match self
            .read_message_archive(queue_id)
            .await
            .and_then(|a| match a {
                Some(a) => a.deserialize::<Message>().map(Some),
                None => Ok(None),
            }) {
            Ok(Some(message)) => Some(MessageWrapper {
                queue_id,
                queue_name,
                span_id: 0,
                message,
            }),
            Ok(None) => None,
            Err(err) => {
                trc::error!(
                    err.details("Failed to read message.")
                        .caused_by(trc::location!())
                );

                None
            }
        }
    }

    async fn read_message_archive(
        &self,
        id: QueueId,
    ) -> trc::Result<Option<Archive<AlignedBytes>>> {
        self.store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(id),
            )))
            .await
    }
}

impl MessageWrapper {
    pub async fn queue(
        mut self,
        raw_headers: Option<&[u8]>,
        raw_message: &[u8],
        session_id: u64,
        server: &Server,
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
        self.message.blob_hash = BlobHash::generate(message.as_ref());

        // Generate id
        if self.message.size == 0 {
            self.message.size = message.len() as u64;
        }

        // Reserve and write blob
        let mut batch = BatchBuilder::new();
        let reserve_until = now() + 120;
        batch.set(
            BlobOp::Reserve {
                hash: self.message.blob_hash.clone(),
                until: reserve_until,
            },
            0u32.serialize(),
        );
        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to write to store.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return false;
        }
        if let Err(err) = server
            .blob_store()
            .put_blob(self.message.blob_hash.as_slice(), message.as_ref())
            .await
        {
            trc::error!(
                err.details("Failed to write blob.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return false;
        }

        trc::event!(
            Queue(match source {
                MessageSource::Authenticated => trc::QueueEvent::QueueMessageAuthenticated,
                MessageSource::Unauthenticated => trc::QueueEvent::QueueMessage,
                MessageSource::Dsn => trc::QueueEvent::QueueDsn,
                MessageSource::Report => trc::QueueEvent::QueueReport,
                MessageSource::Autogenerated => trc::QueueEvent::QueueAutogenerated,
            }),
            SpanId = session_id,
            QueueId = self.queue_id,
            From = if !self.message.return_path.is_empty() {
                trc::Value::String(self.message.return_path.as_str().into())
            } else {
                trc::Value::String("<>".into())
            },
            To = self
                .message
                .recipients
                .iter()
                .map(|r| trc::Value::String(r.address_lcase.as_str().into()))
                .collect::<Vec<_>>(),
            Size = self.message.size,
            NextRetry = self
                .message
                .next_delivery_event(None)
                .map(trc::Value::Timestamp),
            NextDsn = self.message.next_dsn(None).map(trc::Value::Timestamp),
            Expires = self.message.expires(None).map(trc::Value::Timestamp),
        );

        // Write message to queue
        let mut batch = BatchBuilder::new();

        // Reserve quotas
        for quota_key in &self.message.quota_keys {
            match quota_key {
                QuotaKey::Count { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount(key.clone())), 1);
                }
                QuotaKey::Size { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize(key.clone())),
                        self.message.size as i64,
                    );
                }
            }
        }

        for (queue_name, due) in self.message.next_events() {
            batch.set(
                ValueClass::Queue(QueueClass::MessageEvent(store::write::QueueEvent {
                    due,
                    queue_id: self.queue_id,
                    queue_name: queue_name.into_inner(),
                })),
                Vec::new(),
            );
        }

        batch
            .clear(BlobOp::Reserve {
                hash: self.message.blob_hash.clone(),
                until: reserve_until,
            })
            .set(
                BlobOp::LinkId {
                    hash: self.message.blob_hash.clone(),
                    id: self.queue_id,
                },
                vec![],
            )
            .set(
                BlobOp::Commit {
                    hash: self.message.blob_hash.clone(),
                },
                vec![],
            )
            .set(
                ValueClass::Queue(QueueClass::Message(self.queue_id)),
                match Archiver::new(self.message).serialize() {
                    Ok(data) => data,
                    Err(err) => {
                        trc::error!(
                            err.details("Failed to serialize message.")
                                .span_id(session_id)
                                .caused_by(trc::location!())
                        );
                        return false;
                    }
                },
            );

        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to write to store.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return false;
        }

        // Queue the message
        if server
            .inner
            .ipc
            .queue_tx
            .send(QueueEvent::Refresh)
            .await
            .is_err()
        {
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
        server: &Server,
    ) {
        // Resolve queue
        let idx = self.message.recipients.len();
        self.message.recipients.push(Recipient {
            address: rcpt.into(),
            address_lcase: rcpt_lcase.into(),
            status: Status::Scheduled,
            flags: 0,
            orcpt: None,
            retry: Schedule::now(),
            notify: Schedule::now(),
            expires: QueueExpiry::Count(0),
            queue: QueueName::default(),
        });
        let queue = server.get_queue_or_default(
            &server
                .eval_if::<String, _>(
                    &server.core.smtp.queue.queue,
                    &QueueEnvelope::new_rcpt(&self.message, idx),
                    self.span_id,
                )
                .await
                .unwrap_or_else(|| "default".to_string()),
            self.span_id,
        );

        // Update expiration
        let now = now();
        let recipient = self.message.recipients.last_mut().unwrap();
        recipient.notify = Schedule::later(queue.notify.first().copied().unwrap_or(86400) + now);
        recipient.expires = queue.expiry;
        recipient.queue = queue.virtual_queue;
    }

    pub async fn add_recipient(&mut self, rcpt: impl Into<String>, server: &Server) {
        let rcpt = rcpt.into();
        let rcpt_lcase = rcpt.to_lowercase();
        self.add_recipient_parts(rcpt, rcpt_lcase, server).await;
    }

    pub async fn save_changes(mut self, server: &Server, prev_event: Option<u64>) -> bool {
        // Release quota for completed deliveries
        let mut batch = BatchBuilder::new();
        self.release_quota(&mut batch);

        // Update message queue
        if let Some(prev_event) = prev_event {
            batch.clear(ValueClass::Queue(QueueClass::MessageEvent(
                store::write::QueueEvent {
                    due: prev_event,
                    queue_id: self.queue_id,
                    queue_name: self.queue_name.into_inner(),
                },
            )));
        }
        for (queue_name, due) in self.message.next_events() {
            batch.set(
                ValueClass::Queue(QueueClass::MessageEvent(store::write::QueueEvent {
                    due,
                    queue_id: self.queue_id,
                    queue_name: queue_name.into_inner(),
                })),
                Vec::new(),
            );
        }

        let span_id = self.span_id;
        batch.set(
            ValueClass::Queue(QueueClass::Message(self.queue_id)),
            match Archiver::new(self.message).serialize() {
                Ok(data) => data,
                Err(err) => {
                    trc::error!(
                        err.details("Failed to serialize message.")
                            .span_id(span_id)
                            .caused_by(trc::location!())
                    );
                    return false;
                }
            },
        );

        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to save changes.")
                    .span_id(span_id)
                    .caused_by(trc::location!())
            );
            false
        } else {
            true
        }
    }

    pub async fn remove(self, server: &Server, prev_event: Option<u64>) -> bool {
        let mut batch = BatchBuilder::new();

        if let Some(prev_event) = prev_event {
            batch.clear(ValueClass::Queue(QueueClass::MessageEvent(
                store::write::QueueEvent {
                    due: prev_event,
                    queue_id: self.queue_id,
                    queue_name: self.queue_name.into_inner(),
                },
            )));
        } else {
            for (queue_name, due) in self.message.next_events() {
                batch.clear(ValueClass::Queue(QueueClass::MessageEvent(
                    store::write::QueueEvent {
                        due,
                        queue_id: self.queue_id,
                        queue_name: queue_name.into_inner(),
                    },
                )));
            }
        }

        // Release all quotas
        for quota_key in self.message.quota_keys {
            match quota_key {
                QuotaKey::Count { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount(key)), -1);
                }
                QuotaKey::Size { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize(key)),
                        -(self.message.size as i64),
                    );
                }
            }
        }

        batch
            .clear(BlobOp::LinkId {
                hash: self.message.blob_hash.clone(),
                id: self.queue_id,
            })
            .clear(ValueClass::Queue(QueueClass::Message(self.queue_id)));

        if let Err(err) = server.store().write(batch.build_all()).await {
            trc::error!(
                err.details("Failed to write to update queue.")
                    .span_id(self.span_id)
                    .caused_by(trc::location!())
            );
            false
        } else {
            true
        }
    }

    pub fn has_domain(&self, domains: &[String]) -> bool {
        self.message.recipients.iter().any(|r| {
            let domain = r.address_lcase.domain_part();
            domains.iter().any(|dd| dd == domain)
        }) || self
            .message
            .return_path
            .rsplit_once('@')
            .is_some_and(|(_, domain)| domains.iter().any(|dd| dd == domain))
    }
}

impl ArchivedMessage {
    pub fn has_domain(&self, domains: &[String]) -> bool {
        self.recipients.iter().any(|r| {
            let domain = r.address_lcase.domain_part();
            domains.iter().any(|dd| dd == domain)
        }) || self
            .return_path
            .rsplit_once('@')
            .is_some_and(|(_, domain)| domains.iter().any(|dd| dd == domain))
    }

    pub fn next_delivery_event(&self) -> u64 {
        let mut next_delivery = now();

        for (pos, rcpt) in self
            .recipients
            .iter()
            .filter(|d| {
                matches!(
                    d.status,
                    ArchivedStatus::Scheduled | ArchivedStatus::TemporaryFailure(_)
                )
            })
            .enumerate()
        {
            if pos == 0 || rcpt.retry.due < next_delivery {
                next_delivery = rcpt.retry.due.into();
            }
        }

        next_delivery
    }
}
