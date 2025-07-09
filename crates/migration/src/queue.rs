/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::LegacyBincode;
use common::{
    Server,
    config::smtp::queue::{QueueExpiry, QueueName},
};
use smtp::queue::{
    Error, ErrorDetails, HostResponse, Message, QueueId, QuotaKey, Recipient, Schedule, Status,
    UnexpectedResponse,
};
use std::net::{IpAddr, Ipv4Addr};
use store::{
    IterateParams, Serialize, U64_LEN, ValueKey,
    ahash::AHashSet,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, QueueClass, ValueClass,
        key::DeserializeBigEndian, now,
    },
};
use trc::AddContext;
use utils::BlobHash;

pub(crate) async fn migrate_queue(server: &Server) -> trc::Result<()> {
    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
        store::write::QueueEvent {
            due: 0,
            queue_id: 0,
            queue_name: [0; 8],
        },
    )));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
        store::write::QueueEvent {
            due: u64::MAX,
            queue_id: u64::MAX,
            queue_name: [u8::MAX; 8],
        },
    )));

    let mut queue_ids = AHashSet::new();
    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                queue_ids.insert(key.deserialize_be_u64(U64_LEN)?);

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(0)));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX)));
    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                queue_ids.insert(key.deserialize_be_u64(0)?);

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut count = 0;

    for queue_id in queue_ids {
        match server
            .store()
            .get_value::<LegacyBincode<LegacyMessage>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(queue_id),
            )))
            .await
        {
            Ok(Some(bincoded)) => {
                let mut batch = BatchBuilder::new();
                batch.set(
                    ValueClass::Queue(QueueClass::Message(queue_id)),
                    Archiver::new(Message::from(bincoded.inner))
                        .serialize()
                        .caused_by(trc::location!())?,
                );
                count += 1;
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => (),
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                        QueueClass::Message(queue_id),
                    )))
                    .await
                    .is_err()
                {
                    return Err(err
                        .ctx(trc::Key::QueueId, queue_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    if count > 0 {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {count} queued messages",)
        );
    }

    Ok(())
}

impl From<LegacyMessage> for Message {
    fn from(message: LegacyMessage) -> Self {
        let domains = message.domains;
        Message {
            created: message.created,
            blob_hash: message.blob_hash,
            return_path: message.return_path,
            return_path_lcase: message.return_path_lcase,
            return_path_domain: message.return_path_domain,
            recipients: message
                .recipients
                .into_iter()
                .map(|r| {
                    let domain = &domains[r.domain_idx];
                    Recipient {
                        address: r.address,
                        address_lcase: r.address_lcase,
                        status: match r.status {
                            Status::Scheduled => match &domain.status {
                                Status::Scheduled | Status::Completed(_) => Status::Scheduled,
                                Status::TemporaryFailure(err) => Status::TemporaryFailure(
                                    migrate_legacy_error(&domain.domain, err),
                                ),
                                Status::PermanentFailure(err) => Status::PermanentFailure(
                                    migrate_legacy_error(&domain.domain, err),
                                ),
                            },
                            Status::Completed(details) => Status::Completed(details),
                            Status::TemporaryFailure(err) => {
                                Status::TemporaryFailure(migrate_host_response(err))
                            }
                            Status::PermanentFailure(err) => {
                                Status::PermanentFailure(migrate_host_response(err))
                            }
                        },
                        flags: r.flags,
                        orcpt: r.orcpt,
                        retry: domain.retry.clone(),
                        notify: domain.notify.clone(),
                        queue: QueueName::default(),
                        expires: QueueExpiry::Duration(domain.expires.saturating_sub(now())),
                    }
                })
                .collect(),
            flags: message.flags,
            env_id: message.env_id,
            priority: message.priority,
            size: message.size as u64,
            quota_keys: message.quota_keys,
            received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_via_port: 0,
        }
    }
}

fn migrate_legacy_error(domain: &str, err: &LegacyError) -> ErrorDetails {
    match err {
        LegacyError::DnsError(err) => ErrorDetails {
            entity: domain.to_string(),
            details: Error::DnsError(err.clone()),
        },
        LegacyError::UnexpectedResponse(err) => ErrorDetails {
            entity: err.hostname.entity.to_string(),
            details: Error::UnexpectedResponse(UnexpectedResponse {
                command: err.hostname.details.clone(),
                response: err.response.clone(),
            }),
        },
        LegacyError::ConnectionError(err) => ErrorDetails {
            entity: err.entity.to_string(),
            details: Error::ConnectionError(err.details.clone()),
        },
        LegacyError::TlsError(err) => ErrorDetails {
            entity: err.entity.to_string(),
            details: Error::TlsError(err.details.clone()),
        },
        LegacyError::DaneError(err) => ErrorDetails {
            entity: err.entity.to_string(),
            details: Error::DaneError(err.details.clone()),
        },
        LegacyError::MtaStsError(err) => ErrorDetails {
            entity: domain.to_string(),
            details: Error::MtaStsError(err.clone()),
        },
        LegacyError::RateLimited => ErrorDetails {
            entity: domain.to_string(),
            details: Error::RateLimited,
        },
        LegacyError::ConcurrencyLimited => ErrorDetails {
            entity: domain.to_string(),
            details: Error::ConcurrencyLimited,
        },
        LegacyError::Io(err) => ErrorDetails {
            entity: domain.to_string(),
            details: Error::Io(err.clone()),
        },
    }
}

fn migrate_host_response(response: HostResponse<LegacyErrorDetails>) -> ErrorDetails {
    ErrorDetails {
        entity: response.hostname.entity,
        details: Error::UnexpectedResponse(UnexpectedResponse {
            command: response.hostname.details,
            response: response.response,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LegacyMessage {
    pub queue_id: QueueId,
    pub created: u64,
    pub blob_hash: BlobHash,

    pub return_path: String,
    pub return_path_lcase: String,
    pub return_path_domain: String,
    pub recipients: Vec<LegacyRecipient>,
    pub domains: Vec<LegacyDomain>,

    pub flags: u64,
    pub env_id: Option<String>,
    pub priority: i16,

    pub size: usize,
    pub quota_keys: Vec<QuotaKey>,

    #[serde(skip)]
    pub span_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LegacyRecipient {
    pub domain_idx: usize,
    pub address: String,
    pub address_lcase: String,
    pub status: Status<HostResponse<String>, HostResponse<LegacyErrorDetails>>,
    pub flags: u64,
    pub orcpt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LegacyDomain {
    pub domain: String,
    pub retry: Schedule<u32>,
    pub notify: Schedule<u32>,
    pub expires: u64,
    pub status: Status<(), LegacyError>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub enum LegacyError {
    DnsError(String),
    UnexpectedResponse(HostResponse<LegacyErrorDetails>),
    ConnectionError(LegacyErrorDetails),
    TlsError(LegacyErrorDetails),
    DaneError(LegacyErrorDetails),
    MtaStsError(String),
    RateLimited,
    ConcurrencyLimited,
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LegacyErrorDetails {
    pub entity: String,
    pub details: String,
}
