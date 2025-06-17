/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarDuration, ICalendarEntry, ICalendarMethod,
        ICalendarParameter, ICalendarParticipationRole, ICalendarParticipationStatus,
        ICalendarPeriod, ICalendarProperty, ICalendarRecurrenceRule,
        ICalendarScheduleForceSendValue, ICalendarStatus, ICalendarUserTypes, ICalendarValue, Uri,
    },
};
use std::{fmt::Display, hash::Hash};

pub mod attendee;
pub mod event_cancel;
pub mod event_create;
pub mod event_update;
pub mod inbound;
pub mod itip;
pub mod organizer;
pub mod snapshot;

#[derive(Debug)]
pub struct ItipSnapshots<'x> {
    pub organizer: Organizer<'x>,
    pub uid: &'x str,
    pub components: AHashMap<InstanceId, ItipSnapshot<'x>>,
}

#[derive(Debug)]
pub struct ItipSnapshot<'x> {
    pub comp_id: u16,
    pub comp: &'x ICalendarComponent,
    pub attendees: AHashSet<Attendee<'x>>,
    pub dtstamp: Option<&'x PartialDateTime>,
    pub entries: AHashSet<ItipEntry<'x>>,
    pub sequence: Option<i64>,
    pub request_status: Vec<&'x str>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ItipEntry<'x> {
    pub name: &'x ICalendarProperty,
    pub value: ItipEntryValue<'x>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ItipEntryValue<'x> {
    DateTime(ItipDateTime<'x>),
    Period(&'x ICalendarPeriod),
    Duration(&'x ICalendarDuration),
    Status(&'x ICalendarStatus),
    RRule(&'x ICalendarRecurrenceRule),
    Text(&'x str),
    Integer(i64),
}

#[derive(Debug)]
pub struct ItipDateTime<'x> {
    pub date: &'x PartialDateTime,
    pub tz_id: Option<&'x str>,
    pub timestamp: i64,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstanceId {
    Main,
    Recurrence(RecurrenceId),
}

#[derive(Debug, PartialOrd, Ord)]
pub struct RecurrenceId {
    pub entry_id: u16,
    pub date: i64,
    pub this_and_future: bool,
}

#[derive(Debug)]
pub struct Attendee<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub part_stat: Option<&'x ICalendarParticipationStatus>,
    pub delegated_from: Vec<Email>,
    pub delegated_to: Vec<Email>,
    pub role: Option<&'x ICalendarParticipationRole>,
    pub cu_type: Option<&'x ICalendarUserTypes>,
    pub sent_by: Option<Email>,
    pub rsvp: Option<bool>,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Organizer<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Email {
    pub email: String,
    pub is_local: bool,
}

#[derive(Debug)]
pub enum ItipError {
    NoSchedulingInfo,
    OtherSchedulingAgent,
    NotOrganizer,
    NotOrganizerNorAttendee,
    NothingToSend,
    MissingUid,
    MultipleUid,
    MultipleOrganizer,
    MultipleObjectTypes,
    MultipleObjectInstances,
    CannotModifyProperty(ICalendarProperty),
    CannotModifyInstance,
    CannotModifyAddress,
    OrganizerMismatch,
    MissingMethod,
    InvalidComponentType,
    OutOfSequence,
    SenderIsOrganizer,
    SenderIsNotParticipant(String),
    UnknownParticipant(String),
    UnsupportedMethod(ICalendarMethod),
}

pub struct ItipMessage {
    pub method: ICalendarMethod,
    pub from: String,
    pub to: Vec<String>,
    pub changed_properties: Vec<ICalendarProperty>,
    pub message: ICalendar,
}

impl ItipSnapshot<'_> {
    pub fn has_local_attendee(&self) -> bool {
        self.attendees
            .iter()
            .any(|attendee| attendee.email.is_local)
    }

    pub fn local_attendee(&self) -> Option<&Attendee<'_>> {
        self.attendees
            .iter()
            .find(|attendee| attendee.email.is_local)
    }

    pub fn external_attendees(&self) -> impl Iterator<Item = &Attendee<'_>> + '_ {
        self.attendees.iter().filter(|item| !item.email.is_local)
    }
}

impl Attendee<'_> {
    pub fn send_invite_messages(&self) -> bool {
        !self.email.is_local
            && self.is_server_scheduling
            && self.rsvp.is_none_or(|rsvp| rsvp)
            && (self.force_send.is_some()
                || self.part_stat.is_none_or(|part_stat| {
                    part_stat == &ICalendarParticipationStatus::NeedsAction
                }))
    }

    pub fn send_update_messages(&self) -> bool {
        !self.email.is_local
            && self.is_server_scheduling
            && self.rsvp.is_none_or(|rsvp| rsvp)
            && (self.force_send.is_some()
                || self
                    .part_stat
                    .is_none_or(|part_stat| part_stat != &ICalendarParticipationStatus::Declined))
    }

    pub fn is_delegated_from(&self, attendee: &Attendee<'_>) -> bool {
        self.delegated_from
            .iter()
            .any(|d| d.email == attendee.email.email)
    }

    pub fn is_delegated_to(&self, attendee: &Attendee<'_>) -> bool {
        self.delegated_to
            .iter()
            .any(|d| d.email == attendee.email.email)
    }
}

impl Email {
    pub fn new(email: &str, local_addresses: &[&str]) -> Option<Self> {
        email.contains('@').then(|| {
            let email = email.trim().trim_start_matches("mailto:").to_lowercase();
            let is_local = local_addresses.contains(&email.as_str());
            Email { email, is_local }
        })
    }

    pub fn from_uri(uri: &Uri, local_addresses: &[&str]) -> Option<Self> {
        if let Uri::Location(uri) = uri {
            Email::new(uri.as_str(), local_addresses)
        } else {
            None
        }
    }
}

impl PartialEq for Attendee<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
            && self.part_stat == other.part_stat
            && self.delegated_from == other.delegated_from
            && self.delegated_to == other.delegated_to
            && self.role == other.role
            && self.cu_type == other.cu_type
            && self.sent_by == other.sent_by
    }
}

impl Eq for Attendee<'_> {}

impl Hash for Attendee<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.part_stat.hash(state);
        self.delegated_from.hash(state);
        self.delegated_to.hash(state);
        self.role.hash(state);
        self.cu_type.hash(state);
        self.sent_by.hash(state);
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mailto:{}", self.email)
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
    }
}

impl Eq for Email {}

impl PartialEq for RecurrenceId {
    fn eq(&self, other: &Self) -> bool {
        self.date == other.date && self.this_and_future == other.this_and_future
    }
}

impl Eq for RecurrenceId {}

impl Hash for RecurrenceId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.date.hash(state);
        self.this_and_future.hash(state);
    }
}

impl PartialEq for ItipDateTime<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
    }
}
impl Eq for ItipDateTime<'_> {}

impl Hash for ItipDateTime<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.timestamp.hash(state);
    }
}

impl ItipDateTime<'_> {
    pub fn to_entry(&self, name: ICalendarProperty) -> ICalendarEntry {
        ICalendarEntry {
            name,
            params: self
                .tz_id
                .map(|tz_id| vec![ICalendarParameter::Tzid(tz_id.to_string())])
                .unwrap_or_default(),
            values: vec![ICalendarValue::PartialDateTime(Box::new(self.date.clone()))],
        }
    }
}
