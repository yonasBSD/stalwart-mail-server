/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::{atomic::Ordering, Arc, OnceLock},
    thread::{park, Builder, JoinHandle},
    time::SystemTime,
};

use ahash::AHashMap;
use parking_lot::Mutex;

use crate::{
    bitset::{AtomicBitset, USIZE_BITS},
    channel::{EVENT_COUNT, EVENT_RXS},
    subscriber::{Interests, Subscriber},
    DeliveryEvent, Event, EventDetails, EventType, Level, NetworkEvent, TelemetryEvent,
    TOTAL_EVENT_COUNT,
};

pub(crate) type GlobalInterests =
    AtomicBitset<{ (TOTAL_EVENT_COUNT + USIZE_BITS - 1) / USIZE_BITS }>;

pub(crate) static TRACE_INTERESTS: GlobalInterests = GlobalInterests::new();
pub(crate) type CollectorThread = JoinHandle<()>;
pub(crate) static ACTIVE_SUBSCRIBERS: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub(crate) static COLLECTOR_UPDATES: Mutex<Vec<Update>> = Mutex::new(Vec::new());

pub(crate) const EVENT_TYPES: [EventType; TOTAL_EVENT_COUNT] = EventType::variants();

#[allow(clippy::enum_variant_names)]
pub(crate) enum Update {
    Register {
        subscriber: Subscriber,
    },
    Unregister {
        id: String,
    },
    UpdateSubscriber {
        id: String,
        interests: Interests,
        lossy: bool,
    },
    UpdateLevels {
        levels: AHashMap<EventType, Level>,
    },
    Shutdown,
}

pub struct Collector {
    subscribers: Vec<Subscriber>,
    levels: [Level; TOTAL_EVENT_COUNT],
    active_spans: AHashMap<u64, Arc<Event<EventDetails>>>,
}

const EV_CONN_START: usize = EventType::Network(NetworkEvent::ConnectionStart).id();
const EV_CONN_END: usize = EventType::Network(NetworkEvent::ConnectionEnd).id();
const EV_ATTEMPT_START: usize = EventType::Delivery(DeliveryEvent::AttemptStart).id();
const EV_ATTEMPT_END: usize = EventType::Delivery(DeliveryEvent::AttemptEnd).id();
const EV_COLLECTOR_UPDATE: usize = EventType::Telemetry(TelemetryEvent::Update).id();

const STALE_SPAN_CHECK_WATERMARK: usize = 8000;
const SPAN_MAX_HOLD: u64 = 86400;

impl Collector {
    fn collect(&mut self) -> bool {
        if EVENT_COUNT.swap(0, Ordering::Relaxed) == 0 {
            park();
        }

        // Collect all events
        let mut do_continue = true;
        EVENT_RXS.lock().retain_mut(|rx| {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());

            while do_continue {
                match rx.try_recv() {
                    Ok(Some(event)) => {
                        // Build event
                        let event_id = event.inner.id();
                        let mut event = Event {
                            inner: EventDetails {
                                level: self.levels[event_id],
                                typ: event.inner,
                                timestamp,
                                span: None,
                            },
                            keys: event.keys,
                        };

                        // Track spans
                        let event = match event_id {
                            EV_CONN_START | EV_ATTEMPT_START => {
                                let event = Arc::new(event);
                                self.active_spans.insert(
                                    event
                                        .span_id()
                                        .unwrap_or_else(|| panic!("Missing span ID: {event:?}")),
                                    event.clone(),
                                );
                                if self.active_spans.len() > STALE_SPAN_CHECK_WATERMARK {
                                    self.active_spans.retain(|_, span| {
                                        timestamp.saturating_sub(span.inner.timestamp)
                                            < SPAN_MAX_HOLD
                                    });
                                }
                                event
                            }
                            EV_CONN_END | EV_ATTEMPT_END => {
                                if let Some(span) = self
                                    .active_spans
                                    .remove(&event.span_id().expect("Missing span ID"))
                                {
                                    event.inner.span = Some(span.clone());
                                } else {
                                    #[cfg(debug_assertions)]
                                    {
                                        if event.span_id().unwrap() != 0 {
                                            panic!("Unregistered span ID: {event:?}");
                                        }
                                    }
                                }
                                Arc::new(event)
                            }
                            EV_COLLECTOR_UPDATE => {
                                if self.update() {
                                    continue;
                                } else {
                                    do_continue = false;
                                    return false;
                                }
                            }
                            _ => {
                                if let Some(span_id) = event.span_id() {
                                    if let Some(span) = self.active_spans.get(&span_id) {
                                        event.inner.span = Some(span.clone());
                                    } else {
                                        #[cfg(debug_assertions)]
                                        {
                                            if span_id != 0 {
                                                panic!("Unregistered span ID: {event:?}");
                                            }
                                        }
                                    }
                                }

                                Arc::new(event)
                            }
                        };

                        // Send to subscribers
                        for subscriber in self.subscribers.iter_mut() {
                            subscriber.push_event(event_id, event.clone());
                        }
                    }
                    Ok(None) => {
                        return true;
                    }
                    Err(_) => {
                        return false; // Channel is closed, remove.
                    }
                }
            }

            false
        });

        if !self.subscribers.is_empty() {
            if do_continue {
                // Send batched events
                self.subscribers
                    .retain_mut(|subscriber| subscriber.send_batch().is_ok());
            } else {
                // Send remaining events
                for mut subscriber in self.subscribers.drain(..) {
                    let _ = subscriber.send_batch();
                }
            }
        }

        do_continue
    }

    fn update(&mut self) -> bool {
        for update in COLLECTOR_UPDATES.lock().drain(..) {
            match update {
                Update::Register { subscriber } => {
                    ACTIVE_SUBSCRIBERS.lock().push(subscriber.id.clone());
                    self.subscribers.push(subscriber);
                }
                Update::Unregister { id } => {
                    ACTIVE_SUBSCRIBERS.lock().retain(|s| s != &id);
                    self.subscribers.retain(|s| s.id != id);
                }
                Update::UpdateSubscriber {
                    id,
                    interests,
                    lossy,
                } => {
                    for subscriber in self.subscribers.iter_mut() {
                        if subscriber.id == id {
                            subscriber.interests = interests;
                            subscriber.lossy = lossy;
                            break;
                        }
                    }
                }
                Update::UpdateLevels { levels } => {
                    for event in EVENT_TYPES.iter() {
                        let event_id = event.id();
                        if let Some(level) = levels.get(event) {
                            self.levels[event_id] = *level;
                        } else {
                            self.levels[event_id] = event.level();
                        }
                    }
                }
                Update::Shutdown => return false,
            }
        }

        true
    }

    pub fn set_interests(mut interests: Interests) {
        if !interests.is_empty() {
            for event_type in [
                EventType::Network(NetworkEvent::ConnectionStart),
                EventType::Network(NetworkEvent::ConnectionEnd),
                EventType::Delivery(DeliveryEvent::AttemptStart),
                EventType::Delivery(DeliveryEvent::AttemptEnd),
            ] {
                interests.set(event_type);
            }
        }

        TRACE_INTERESTS.update(interests);
    }

    pub fn union_interests(interests: Interests) {
        TRACE_INTERESTS.union(interests);
    }

    #[inline(always)]
    pub fn has_interest(event: impl Into<usize>) -> bool {
        TRACE_INTERESTS.get(event)
    }

    pub fn get_subscribers() -> Vec<String> {
        ACTIVE_SUBSCRIBERS.lock().clone()
    }

    pub fn update_custom_levels(levels: AHashMap<EventType, Level>) {
        COLLECTOR_UPDATES
            .lock()
            .push(Update::UpdateLevels { levels });
    }

    pub fn update_subscriber(id: String, interests: Interests, lossy: bool) {
        COLLECTOR_UPDATES.lock().push(Update::UpdateSubscriber {
            id,
            interests,
            lossy,
        });
    }

    pub fn remove_subscriber(id: String) {
        COLLECTOR_UPDATES.lock().push(Update::Unregister { id });
    }

    pub fn shutdown() {
        COLLECTOR_UPDATES.lock().push(Update::Shutdown);
        Collector::reload();
    }

    pub fn is_enabled() -> bool {
        !TRACE_INTERESTS.is_empty()
    }

    pub fn reload() {
        Event::new(EventType::Telemetry(TelemetryEvent::Update)).send()
    }
}

pub(crate) fn spawn_collector() -> &'static Arc<CollectorThread> {
    static COLLECTOR: OnceLock<Arc<CollectorThread>> = OnceLock::new();
    COLLECTOR.get_or_init(|| {
        Arc::new(
            Builder::new()
                .name("stalwart-collector".to_string())
                .spawn(move || {
                    let mut collector = Collector::default();

                    while collector.collect() {}
                })
                .expect("Failed to start event collector"),
        )
    })
}

impl Default for Collector {
    fn default() -> Self {
        let mut c = Collector {
            subscribers: Vec::new(),
            levels: [Level::Disable; TOTAL_EVENT_COUNT],
            active_spans: AHashMap::new(),
        };

        for event in EVENT_TYPES.iter() {
            let event_id = event.id();
            c.levels[event_id] = event.level();
        }

        c
    }
}
