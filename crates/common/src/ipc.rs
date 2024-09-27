/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, sync::Arc, time::Instant};

use ahash::RandomState;
use jmap_proto::types::{state::StateChange, type_state::DataType};
use mail_auth::{
    dmarc::Dmarc,
    mta_sts::TlsRpt,
    report::{tlsrpt::FailureDetails, Record},
};
use store::{BlobStore, LookupStore, Store};
use tokio::sync::{mpsc, oneshot};
use utils::{map::bitmap::Bitmap, BlobHash};

use crate::{
    config::smtp::{
        report::AggregateFrequency,
        resolver::{Policy, Tlsa},
    },
    listener::limiter::ConcurrencyLimiter,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryResult {
    Success,
    TemporaryFailure {
        reason: Cow<'static, str>,
    },
    PermanentFailure {
        code: [u8; 3],
        reason: Cow<'static, str>,
    },
}

#[derive(Debug)]
pub enum DeliveryEvent {
    Ingest {
        message: IngestMessage,
        result_tx: oneshot::Sender<Vec<DeliveryResult>>,
    },
    Stop,
}

#[derive(Debug)]
pub struct IngestMessage {
    pub sender_address: String,
    pub recipients: Vec<String>,
    pub message_blob: BlobHash,
    pub message_size: usize,
    pub session_id: u64,
}

pub enum HousekeeperEvent {
    AcmeReschedule {
        provider_id: String,
        renew_at: Instant,
    },
    Purge(PurgeType),
    ReloadSettings,
    Exit,
}

pub enum PurgeType {
    Data(Store),
    Blobs { store: Store, blob_store: BlobStore },
    Lookup(LookupStore),
    Account(Option<u32>),
}

#[derive(Debug)]
pub enum StateEvent {
    Subscribe {
        account_id: u32,
        types: Bitmap<DataType>,
        tx: mpsc::Sender<StateChange>,
    },
    Publish {
        state_change: StateChange,
    },
    UpdateSharedAccounts {
        account_id: u32,
    },
    UpdateSubscriptions {
        account_id: u32,
        subscriptions: Vec<UpdateSubscription>,
    },
    Stop,
}

#[derive(Debug)]
pub enum UpdateSubscription {
    Unverified {
        id: u32,
        url: String,
        code: String,
        keys: Option<EncryptionKeys>,
    },
    Verified(PushSubscription),
}

#[derive(Debug)]
pub struct PushSubscription {
    pub id: u32,
    pub url: String,
    pub expires: u64,
    pub types: Bitmap<DataType>,
    pub keys: Option<EncryptionKeys>,
}

#[derive(Debug, Clone)]
pub struct EncryptionKeys {
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
}

#[derive(Debug)]
pub enum QueueEvent {
    Reload,
    OnHold(OnHold<QueueEventLock>),
    Stop,
}

#[derive(Debug)]
pub struct OnHold<T> {
    pub next_due: Option<u64>,
    pub limiters: Vec<ConcurrencyLimiter>,
    pub message: T,
}

#[derive(Debug)]
pub struct QueueEventLock {
    pub due: u64,
    pub queue_id: u64,
    pub lock_expiry: u64,
}

#[derive(Debug)]
pub enum ReportingEvent {
    Dmarc(Box<DmarcEvent>),
    Tls(Box<TlsEvent>),
    Stop,
}

#[derive(Debug)]
pub struct DmarcEvent {
    pub domain: String,
    pub report_record: Record,
    pub dmarc_record: Arc<Dmarc>,
    pub interval: AggregateFrequency,
}

#[derive(Debug)]
pub struct TlsEvent {
    pub domain: String,
    pub policy: PolicyType,
    pub failure: Option<FailureDetails>,
    pub tls_record: Arc<TlsRpt>,
    pub interval: AggregateFrequency,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum PolicyType {
    Tlsa(Option<Arc<Tlsa>>),
    Sts(Option<Arc<Policy>>),
    None,
}

pub trait ToHash {
    fn to_hash(&self) -> u64;
}

impl ToHash for Dmarc {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
    }
}

impl ToHash for PolicyType {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
    }
}

impl From<DmarcEvent> for ReportingEvent {
    fn from(value: DmarcEvent) -> Self {
        ReportingEvent::Dmarc(Box::new(value))
    }
}

impl From<TlsEvent> for ReportingEvent {
    fn from(value: TlsEvent) -> Self {
        ReportingEvent::Tls(Box::new(value))
    }
}

impl From<Arc<Tlsa>> for PolicyType {
    fn from(value: Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value))
    }
}

impl From<Arc<Policy>> for PolicyType {
    fn from(value: Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value))
    }
}

impl From<&Arc<Tlsa>> for PolicyType {
    fn from(value: &Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value.clone()))
    }
}

impl From<&Arc<Policy>> for PolicyType {
    fn from(value: &Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value.clone()))
    }
}

impl From<(&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)> for PolicyType {
    fn from(value: (&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)) -> Self {
        match value {
            (Some(value), _) => PolicyType::Sts(Some(value.clone())),
            (_, Some(value)) => PolicyType::Tlsa(Some(value.clone())),
            _ => PolicyType::None,
        }
    }
}
