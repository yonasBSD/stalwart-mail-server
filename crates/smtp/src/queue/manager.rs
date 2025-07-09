/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Message, QueueId, Status,
    spool::{QUEUE_REFRESH, SmtpSpool},
};
use crate::queue::Recipient;
use ahash::AHashMap;
use common::{
    Inner,
    config::smtp::queue::{QueueExpiry, QueueName},
    core::BuildServer,
    ipc::{QueueEvent, QueueEventStatus},
};
use rand::seq::SliceRandom;
use std::{
    collections::hash_map::Entry,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use store::write::now;
use tokio::sync::mpsc;

pub struct Queue {
    pub core: Arc<Inner>,
    pub on_hold: AHashMap<QueueId, OnHold>,
    pub next_wake_up: Instant,
    pub rx: mpsc::Receiver<QueueEvent>,
}

#[derive(Debug)]
pub enum OnHold {
    InFlight,
    Locked { until: u64 },
}

impl SpawnQueue for mpsc::Receiver<QueueEvent> {
    fn spawn(self, core: Arc<Inner>) {
        tokio::spawn(async move {
            Queue::new(core, self).start().await;
        });
    }
}

const CLEANUP_INTERVAL: Duration = Duration::from_secs(10 * 60);
const BACK_PRESSURE_WARN_INTERVAL: Duration = Duration::from_secs(60);

impl Queue {
    pub fn new(core: Arc<Inner>, rx: mpsc::Receiver<QueueEvent>) -> Self {
        Queue {
            core,
            on_hold: AHashMap::with_capacity(128),
            next_wake_up: Instant::now(),
            rx,
        }
    }

    pub async fn start(&mut self) {
        let mut is_paused = false;
        let mut next_cleanup = Instant::now() + CLEANUP_INTERVAL;
        let mut last_backpressure_warning = Instant::now() - BACK_PRESSURE_WARN_INTERVAL;
        let mut in_flight_count = 0;
        let mut has_back_pressure = false;

        loop {
            let refresh_queue = match tokio::time::timeout(
                self.next_wake_up.duration_since(Instant::now()),
                self.rx.recv(),
            )
            .await
            {
                Ok(Some(QueueEvent::WorkerDone { queue_id, status })) => {
                    in_flight_count -= 1;

                    match status {
                        QueueEventStatus::Completed => {
                            self.on_hold.remove(&queue_id);
                            !self.on_hold.is_empty() || has_back_pressure
                        }
                        QueueEventStatus::Locked { until } => {
                            let due_in = Instant::now() + Duration::from_secs(until - now());
                            if due_in < self.next_wake_up {
                                self.next_wake_up = due_in;
                            }

                            self.on_hold.insert(queue_id, OnHold::Locked { until });
                            self.on_hold.len() > 1 || has_back_pressure
                        }
                        QueueEventStatus::Deferred => {
                            self.on_hold.remove(&queue_id);
                            true
                        }
                    }
                }
                Ok(Some(QueueEvent::Refresh)) => true,
                Ok(Some(QueueEvent::Paused(paused))) => {
                    self.core
                        .data
                        .queue_status
                        .store(!paused, Ordering::Relaxed);
                    is_paused = paused;
                    false
                }
                Err(_) => true,
                Ok(Some(QueueEvent::Stop)) | Ok(None) => {
                    break;
                }
            };

            if !is_paused {
                // Deliver scheduled messages
                if refresh_queue || self.next_wake_up <= Instant::now() {
                    // If the number of in-flight messages is greater than the maximum allowed, skip the queue
                    let server = self.core.build_server();
                    let todo = "fix + implement virtual queues";
                    let max_in_flight = 4; //server.core.smtp.queue.max_threads;
                    has_back_pressure = in_flight_count >= max_in_flight;
                    if has_back_pressure {
                        self.next_wake_up = Instant::now() + Duration::from_secs(QUEUE_REFRESH);

                        if last_backpressure_warning.elapsed() >= BACK_PRESSURE_WARN_INTERVAL {
                            let queue_events = server.next_event().await;
                            last_backpressure_warning = Instant::now();
                            trc::event!(
                                Queue(trc::QueueEvent::BackPressure),
                                Reason =
                                    "Queue outbound processing capacity for this node exceeded.",
                                Total = queue_events.len(),
                                Details = self
                                    .on_hold
                                    .values()
                                    .fold([0, 0], |mut acc, v| {
                                        match v {
                                            OnHold::InFlight => acc[0] += 1,
                                            OnHold::Locked { .. } => acc[1] += 1,
                                        }
                                        acc
                                    })
                                    .into_iter()
                                    .map(trc::Value::from)
                                    .collect::<Vec<_>>(),
                                Limit = max_in_flight,
                            );
                        }
                        continue;
                    }

                    // Process queue events
                    let now = now();
                    let mut next_wake_up = QUEUE_REFRESH;
                    let mut queue_events = server.next_event().await;

                    if queue_events.len() > 5 {
                        queue_events.shuffle(&mut rand::rng());
                    }

                    for queue_event in &queue_events {
                        if queue_event.due <= now {
                            // Enforce global concurrency limits
                            if in_flight_count >= max_in_flight {
                                has_back_pressure = true;
                                if last_backpressure_warning.elapsed()
                                    >= BACK_PRESSURE_WARN_INTERVAL
                                {
                                    last_backpressure_warning = Instant::now();
                                    trc::event!(
                                        Queue(trc::QueueEvent::BackPressure),
                                        Reason = "Queue outbound processing capacity for this node exceeded.",
                                        Total = queue_events.len(),
                                        Details = self
                                            .on_hold
                                            .values()
                                            .fold([0, 0], |mut acc, v| {
                                                match v {
                                                    OnHold::InFlight => acc[0] += 1,
                                                    OnHold::Locked { .. } => acc[1] += 1,
                                                }
                                                acc
                                            })
                                            .into_iter()
                                            .map(trc::Value::from)
                                            .collect::<Vec<_>>(),
                                        Limit = max_in_flight,
                                    );
                                }
                                break;
                            }

                            // Check if the message is still on hold
                            if let Some(on_hold) = self.on_hold.get(&queue_event.queue_id) {
                                match on_hold {
                                    OnHold::Locked { until } => {
                                        if *until > now {
                                            let due_in = *until - now;
                                            if due_in < next_wake_up {
                                                next_wake_up = due_in;
                                            }
                                            continue;
                                        }
                                    }
                                    OnHold::InFlight => continue,
                                }

                                self.on_hold.remove(&queue_event.queue_id);
                            }

                            // Deliver message
                            in_flight_count += 1;
                            self.on_hold.insert(queue_event.queue_id, OnHold::InFlight);
                            queue_event.try_deliver(server.clone());
                        } else {
                            let due_in = queue_event.due - now;
                            if due_in < next_wake_up {
                                next_wake_up = due_in;
                            }
                        }
                    }

                    // Remove expired locks
                    let now = Instant::now();
                    if next_cleanup <= now {
                        next_cleanup = now + CLEANUP_INTERVAL;

                        if !self.on_hold.is_empty() {
                            let now = store::write::now();
                            self.on_hold.retain(|queue_id, status| match status {
                                OnHold::InFlight => true,
                                OnHold::Locked { until } => *until > now,
                            });
                        }
                    }

                    self.next_wake_up = now + Duration::from_secs(next_wake_up);
                }
            } else {
                // Queue is paused
                self.next_wake_up = Instant::now() + Duration::from_secs(86400);
            }
        }
    }
}

impl Message {
    pub fn next_event(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_event = None;

        for rcpt in &self.recipients {
            if matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| rcpt.queue == q)
            {
                let mut earlier_event = std::cmp::min(rcpt.retry.due, rcpt.notify.due);

                if let Some(expires) = rcpt.expiration_time(self.created) {
                    earlier_event = std::cmp::min(earlier_event, expires);
                }

                if let Some(next_event) = &mut next_event {
                    if earlier_event < *next_event {
                        *next_event = earlier_event;
                    }
                } else {
                    next_event = Some(earlier_event);
                }
            }
        }

        next_event
    }

    pub fn next_delivery_event(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_delivery = None;

        for rcpt in self.recipients.iter().filter(|rcpt| {
            matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| rcpt.queue == q)
        }) {
            if let Some(next_delivery) = &mut next_delivery {
                if rcpt.retry.due < *next_delivery {
                    *next_delivery = rcpt.retry.due;
                }
            } else {
                next_delivery = Some(rcpt.retry.due);
            }
        }

        next_delivery
    }

    pub fn next_dsn(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_dsn = None;

        for rcpt in self.recipients.iter().filter(|rcpt| {
            matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| rcpt.queue == q)
        }) {
            if let Some(next_dsn) = &mut next_dsn {
                if rcpt.notify.due < *next_dsn {
                    *next_dsn = rcpt.notify.due;
                }
            } else {
                next_dsn = Some(rcpt.notify.due);
            }
        }

        next_dsn
    }

    pub fn expires(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut expires = None;

        for rcpt in self.recipients.iter().filter(|d| {
            matches!(d.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| d.queue == q)
        }) {
            if let Some(rcpt_expires) = rcpt.expiration_time(self.created) {
                if let Some(expires) = &mut expires {
                    if rcpt_expires > *expires {
                        *expires = rcpt_expires;
                    }
                } else {
                    expires = Some(rcpt_expires)
                }
            }
        }

        expires
    }

    pub fn next_event_after(&self, queue: Option<QueueName>, instant: u64) -> Option<u64> {
        let mut next_event = None;

        for rcpt in &self.recipients {
            if matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
                && queue.is_none_or(|q| rcpt.queue == q)
            {
                if rcpt.retry.due > instant
                    && next_event.as_ref().is_none_or(|ne| rcpt.retry.due.lt(ne))
                {
                    next_event = rcpt.retry.due.into();
                }
                if rcpt.notify.due > instant
                    && next_event.as_ref().is_none_or(|ne| rcpt.notify.due.lt(ne))
                {
                    next_event = rcpt.notify.due.into();
                }
                if let Some(expires) = rcpt.expiration_time(self.created) {
                    if expires > instant && next_event.as_ref().is_none_or(|ne| expires.lt(ne)) {
                        next_event = expires.into();
                    }
                }
            }
        }

        next_event
    }

    pub fn next_events(&self) -> AHashMap<QueueName, u64> {
        let mut next_events = AHashMap::new();

        for rcpt in &self.recipients {
            if matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_)) {
                let mut earlier_event = std::cmp::min(rcpt.retry.due, rcpt.notify.due);

                if let Some(expires) = rcpt.expiration_time(self.created) {
                    earlier_event = std::cmp::min(earlier_event, expires);
                }

                match next_events.entry(rcpt.queue) {
                    Entry::Occupied(mut entry) => {
                        let entry = entry.get_mut();
                        if earlier_event < *entry {
                            *entry = earlier_event;
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(earlier_event);
                    }
                }
            }
        }

        next_events
    }
}

impl Recipient {
    pub fn expiration_time(&self, created: u64) -> Option<u64> {
        match self.expires {
            QueueExpiry::Duration(time) => Some(created + time),
            QueueExpiry::Count(_) => None,
        }
    }

    pub fn is_expired(&self, created: u64, now: u64) -> bool {
        match self.expires {
            QueueExpiry::Duration(time) => created + time <= now,
            QueueExpiry::Count(count) => self.retry.inner >= count,
        }
    }
}

pub trait SpawnQueue {
    fn spawn(self, core: Arc<Inner>);
}
