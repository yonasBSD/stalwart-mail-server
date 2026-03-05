/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{KV_LOCK_TASK, Server};
use registry::schema::enums::TaskType;
use registry::schema::structs::Task;
use registry::types::EnumImpl;
use std::future::Future;
use std::time::Instant;
use store::write::Operation;
use store::xxhash_rust::xxh3::xxh3_64;
use store::{ahash::AHashMap, write::now};
use tokio::sync::mpsc;
use trc::TaskManagerEvent;

pub mod alarm;
pub mod destroy_account;
pub mod imip;
pub mod index;
pub mod lock;
pub mod maintenance;
pub mod manager;
pub mod merge_threads;
pub mod report;
pub mod restore_item;
pub mod scheduler;
pub mod spam_classifier;

const QUEUE_REFRESH_INTERVAL: u64 = 60 * 5; // 5 minutes
const DEFAULT_LOCK_EXPIRY: u64 = 60 * 5; // 5 minutes

pub(crate) struct TaskManagerIpc {
    txs: [mpsc::Sender<TaskJob>; TaskType::COUNT],
    locked: AHashMap<u64, Locked>,
    revision: u64,
}

pub(crate) struct Locked {
    expires: Instant,
    revision: u64,
}

pub(crate) struct TaskDetails {
    task: Task,
    info: TaskJob,
}

pub(crate) struct TaskJob {
    id: u64,
    due: u64,
    typ: TaskType,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TaskResult {
    Success,
    Update([Operation; 2]),
    Failure {
        typ: TaskFailureType,
        message: String,
    },
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TaskFailureType {
    Retry(u64),
    Temporary,
    Permanent,
}

pub(crate) trait TaskInfo {
    fn name(&self) -> &'static str;
}

impl TaskInfo for Task {
    fn name(&self) -> &'static str {
        match self {
            Task::IndexDocument(_) => "IndexDocument",
            Task::UnindexDocument(_) => "UnindexDocument",
            Task::IndexTrace(_) => "IndexTrace",
            Task::CalendarAlarmEmail(_) => "CalendarAlarmEmail",
            Task::CalendarAlarmNotification(_) => "CalendarAlarmNotification",
            Task::CalendarItipMessage(_) => "CalendarItipMessage",
            Task::MergeThreads(_) => "MergeThreads",
            Task::DmarcReport(_) => "DmarcReport",
            Task::TlsReport(_) => "TlsReport",
            Task::RestoreArchivedItem(_) => "RestoreArchivedItem",
            Task::DestroyAccount(_) => "DestroyAccount",
            Task::AccountMaintenance(_) => "AccountMaintenance",
            Task::StoreMaintenance(_) => "StoreMaintenance",
            Task::SpamFilterMaintenance(_) => "SpamFilterMaintenance",
        }
    }
}

impl TaskResult {
    pub fn permanent(message: impl Into<String>) -> Self {
        TaskResult::Failure {
            typ: TaskFailureType::Permanent,
            message: message.into(),
        }
    }

    pub fn temporary(message: impl Into<String>) -> Self {
        TaskResult::Failure {
            typ: TaskFailureType::Temporary,
            message: message.into(),
        }
    }
}

impl TaskJob {
    #[inline(always)]
    pub fn id_hash(&self) -> u64 {
        xxh3_64(&self.id.to_le_bytes())
    }
}
