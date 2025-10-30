/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendar, ArchivedCalendarEvent, ArchivedCalendarPreferences, ArchivedDefaultAlert,
    ArchivedTimezone, Calendar, CalendarEvent, CalendarPreferences, DefaultAlert, Timezone,
};
use crate::calendar::{
    ArchivedCalendarEventNotification, ArchivedEventPreferences, CalendarEventNotification,
    EventPreferences,
};
use calcard::icalendar::{
    ArchivedICalendarParameterValue, ArchivedICalendarProperty, ArchivedICalendarValue,
    ICalendarParameterValue, ICalendarProperty, ICalendarValue,
};
use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use store::{
    write::{IndexPropertyClass, ValueClass},
    xxhash_rust::xxh3,
};
use types::{acl::AclGrant, collection::SyncCollection, field::CalendarNotificationField};

impl IndexableObject for Calendar {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.preferences.iter().map(|p| p.size()).sum::<usize>() as u32
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Calendar,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendar {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.preferences.iter().map(|p| p.size()).sum::<usize>() as u32
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::Calendar,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for Calendar {
    fn is_versioned() -> bool {
        true
    }
}

impl IndexableObject for CalendarEvent {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::SearchIndex {
                hashes: self.hashes().collect(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.preferences.iter().map(|p| p.size()).sum::<usize>() as u32
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendarEvent {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::SearchIndex {
                hashes: self.hashes().collect(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.preferences.iter().map(|p| p.size()).sum::<usize>() as u32
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::Calendar,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for CalendarEvent {
    fn is_versioned() -> bool {
        true
    }
}

impl IndexableObject for CalendarEventNotification {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Quota { used: self.size },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: CalendarNotificationField::CreatedToId.into(),
                    value: self.created as u64,
                }),
                value: self.event_id.unwrap_or(u32::MAX).into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::CalendarEventNotification,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedCalendarEventNotification {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Quota {
                used: self.size.to_native(),
            },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: CalendarNotificationField::CreatedToId.into(),
                    value: self.created.to_native() as u64,
                }),
                value: self
                    .event_id
                    .as_ref()
                    .map(|v| v.to_native())
                    .unwrap_or(u32::MAX)
                    .into(),
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::CalendarEventNotification,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for CalendarEventNotification {
    fn is_versioned() -> bool {
        false
    }
}

impl CalendarPreferences {
    pub fn size(&self) -> usize {
        self.name.len()
            + self.default_alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.description.as_ref().map_or(0, |n| n.len())
            + self.color.as_ref().map_or(0, |n| n.len())
            + self.time_zone.size()
            + std::mem::size_of::<CalendarPreferences>()
    }
}

impl ArchivedCalendarPreferences {
    pub fn size(&self) -> usize {
        self.name.len()
            + self.default_alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.description.as_ref().map_or(0, |n| n.len())
            + self.color.as_ref().map_or(0, |n| n.len())
            + self.time_zone.size()
            + std::mem::size_of::<CalendarPreferences>()
    }
}

impl EventPreferences {
    pub fn size(&self) -> usize {
        self.alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.properties.iter().map(|p| p.size()).sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }
}

impl ArchivedEventPreferences {
    pub fn size(&self) -> usize {
        self.alerts.iter().map(|a| a.size()).sum::<usize>()
            + self.properties.iter().map(|p| p.size()).sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }
}

impl Timezone {
    pub fn size(&self) -> usize {
        match self {
            Timezone::IANA(_) => 2,
            Timezone::Custom(c) => c.size(),
            Timezone::Default => 0,
        }
    }
}

impl ArchivedTimezone {
    pub fn size(&self) -> usize {
        match self {
            ArchivedTimezone::IANA(_) => 2,
            ArchivedTimezone::Custom(c) => c.size(),
            ArchivedTimezone::Default => 0,
        }
    }
}

impl DefaultAlert {
    pub fn size(&self) -> usize {
        std::mem::size_of::<DefaultAlert>() + self.id.len()
    }
}

impl ArchivedDefaultAlert {
    pub fn size(&self) -> usize {
        std::mem::size_of::<DefaultAlert>() + self.id.len()
    }
}

impl CalendarEvent {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.data
            .event
            .components
            .iter()
            .filter(|e| e.component_type.is_scheduling_object())
            .flat_map(|e| {
                e.entries.iter().filter(|e| {
                    matches!(
                        e.name,
                        ICalendarProperty::Summary
                            | ICalendarProperty::Location
                            | ICalendarProperty::Description
                            | ICalendarProperty::Categories
                            | ICalendarProperty::Comment
                            | ICalendarProperty::Attendee
                            | ICalendarProperty::Organizer
                    )
                })
            })
            .flat_map(|e| {
                e.values
                    .iter()
                    .filter_map(|v| match v {
                        ICalendarValue::Text(v) => Some(v.as_str()),
                        ICalendarValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    })
                    .chain(e.params.iter().filter_map(|p| match &p.value {
                        ICalendarParameterValue::Text(v) => Some(v.as_str()),
                        ICalendarParameterValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    }))
            })
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }
}

impl ArchivedCalendarEvent {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.data
            .event
            .components
            .iter()
            .filter(|e| e.component_type.is_scheduling_object())
            .flat_map(|e| {
                e.entries.iter().filter(|e| {
                    matches!(
                        e.name,
                        ArchivedICalendarProperty::Summary
                            | ArchivedICalendarProperty::Location
                            | ArchivedICalendarProperty::Description
                            | ArchivedICalendarProperty::Categories
                            | ArchivedICalendarProperty::Comment
                            | ArchivedICalendarProperty::Attendee
                            | ArchivedICalendarProperty::Organizer
                    )
                })
            })
            .flat_map(|e| {
                e.values
                    .iter()
                    .filter_map(|v| match v {
                        ArchivedICalendarValue::Text(v) => Some(v.as_str()),
                        ArchivedICalendarValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    })
                    .chain(e.params.iter().filter_map(|p| match &p.value {
                        ArchivedICalendarParameterValue::Text(v) => Some(v.as_str()),
                        ArchivedICalendarParameterValue::Uri(uri) => uri.as_str(),
                        _ => None,
                    }))
            })
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }
}
