/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard};
use ahash::AHashSet;
use calcard::{
    common::IanaString,
    vcard::{
        ArchivedVCardParameterValue, ArchivedVCardProperty, ArchivedVCardValue,
        VCardParameterValue, VCardProperty,
    },
};
use common::storage::index::{IndexValue, IndexableAndSerializableObject, IndexableObject};
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use store::{
    search::{ContactSearchField, IndexDocument, SearchField},
    write::{IndexPropertyClass, SearchIndex, ValueClass},
    xxhash_rust::xxh3,
};
use types::{acl::AclGrant, collection::SyncCollection, field::ContactField};
use utils::sanitize_email;

impl IndexableObject for AddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self
                        .preferences
                        .iter()
                        .map(|p| {
                            p.name.len() as u32
                                + p.description.as_ref().map_or(0, |n| n.len() as u32)
                        })
                        .sum::<u32>()
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::AddressBook,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedAddressBook {
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
                    + self
                        .preferences
                        .iter()
                        .map(|p| {
                            p.name.len() as u32
                                + p.description.as_ref().map_or(0, |n| n.len() as u32)
                        })
                        .sum::<u32>()
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::AddressBook,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for AddressBook {
    fn is_versioned() -> bool {
        true
    }
}

impl IndexableObject for ContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: ContactField::Uid.into(),
                value: self.card.uid().into(),
            },
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: self.emails().next().into(),
            },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: ContactField::CreatedToUpdated.into(),
                    value: self.created as u64,
                }),
                value: self.modified.into(),
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: self.hashes().fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: ContactField::Uid.into(),
                value: self.card.uid().into(),
            },
            IndexValue::Index {
                field: ContactField::Email.into(),
                value: self.emails().next().into(),
            },
            IndexValue::Property {
                field: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: ContactField::CreatedToUpdated.into(),
                    value: self.created.to_native() as u64,
                }),
                value: (self.modified.to_native() as u64).into(),
            },
            IndexValue::SearchIndex {
                index: SearchIndex::Contacts,
                hash: self.hashes().fold(0, |acc, hash| acc ^ hash),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for ContactCard {
    fn is_versioned() -> bool {
        true
    }
}

impl ContactCard {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.card
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.name,
                    VCardProperty::Adr
                        | VCardProperty::N
                        | VCardProperty::Fn
                        | VCardProperty::Title
                        | VCardProperty::Org
                        | VCardProperty::Note
                        | VCardProperty::Nickname
                        | VCardProperty::Email
                        | VCardProperty::Kind
                        | VCardProperty::Uid
                        | VCardProperty::Member
                        | VCardProperty::Impp
                        | VCardProperty::Socialprofile
                        | VCardProperty::Tel
                )
            })
            .flat_map(|e| {
                e.values
                    .iter()
                    .filter_map(|v| v.as_text())
                    .chain(e.params.iter().filter_map(|p| match &p.value {
                        VCardParameterValue::Text(v) => Some(v.as_str()),
                        _ => None,
                    }))
            })
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }

    pub fn emails(&self) -> impl Iterator<Item = String> {
        self.card.properties(&VCardProperty::Email).flat_map(|e| {
            e.values
                .iter()
                .filter_map(|v| v.as_text().and_then(sanitize_email))
        })
    }
}

impl ArchivedContactCard {
    pub fn hashes(&self) -> impl Iterator<Item = u64> {
        self.card
            .entries
            .iter()
            .filter(|e| {
                matches!(
                    e.name,
                    ArchivedVCardProperty::Adr
                        | ArchivedVCardProperty::N
                        | ArchivedVCardProperty::Fn
                        | ArchivedVCardProperty::Title
                        | ArchivedVCardProperty::Org
                        | ArchivedVCardProperty::Note
                        | ArchivedVCardProperty::Nickname
                        | ArchivedVCardProperty::Email
                        | ArchivedVCardProperty::Kind
                        | ArchivedVCardProperty::Uid
                        | ArchivedVCardProperty::Member
                        | ArchivedVCardProperty::Impp
                        | ArchivedVCardProperty::Socialprofile
                        | ArchivedVCardProperty::Tel
                )
            })
            .flat_map(|e| {
                e.values
                    .iter()
                    .filter_map(|v| v.as_text())
                    .chain(e.params.iter().filter_map(|p| match &p.value {
                        ArchivedVCardParameterValue::Text(v) => Some(v.as_str()),
                        _ => None,
                    }))
            })
            .map(|v| xxh3::xxh3_64(v.as_bytes()))
    }

    pub fn emails(&self) -> impl Iterator<Item = String> {
        self.card.properties(&VCardProperty::Email).flat_map(|e| {
            e.values
                .iter()
                .filter_map(|v| v.as_text().and_then(sanitize_email))
        })
    }
}

impl ArchivedContactCard {
    pub fn index_document(&self, index_fields: &AHashSet<SearchField>) -> IndexDocument {
        let mut document = IndexDocument::new(SearchIndex::Contacts);
        let mut detector = LanguageDetector::new();

        for entry in self.card.entries.iter() {
            let (is_text, field) = SearchField::Contact(match entry.name {
                ArchivedVCardProperty::N => (false, ContactSearchField::Name),
                ArchivedVCardProperty::Nickname => (false, ContactSearchField::Nickname),
                ArchivedVCardProperty::Org => (false, ContactSearchField::Organization),
                ArchivedVCardProperty::Email => (false, ContactSearchField::Email),
                ArchivedVCardProperty::Tel => (false, ContactSearchField::Phone),
                ArchivedVCardProperty::Impp | ArchivedVCardProperty::Socialprofile => {
                    (false, ContactSearchField::OnlineService)
                }
                ArchivedVCardProperty::Adr => (false, ContactSearchField::Address),
                ArchivedVCardProperty::Note => (true, ContactSearchField::Note),
                ArchivedVCardProperty::Kind => (false, ContactSearchField::Kind),
                ArchivedVCardProperty::Uid => (false, ContactSearchField::Uid),
                ArchivedVCardProperty::Member => (false, ContactSearchField::Member),
                _ => continue,
            });

            if index_fields.is_empty() || index_fields.contains(&field) {
                for value in entry.values.iter() {
                    match value {
                        ArchivedVCardValue::Text(v) => {
                            let lang = if is_text {
                                detector.detect(v.as_str(), MIN_LANGUAGE_SCORE);
                                Language::Unknown
                            } else {
                                Language::None
                            };

                            document.index_text(field.clone(), v, lang);
                        }
                        ArchivedVCardValue::Kind(v) => {
                            document.index_text(field.clone(), v.as_str(), Language::None);
                        }
                        ArchivedVCardValue::Component(v) => {
                            for item in v.iter() {
                                document.index_text(field.clone(), item, Language::None);
                            }
                        }
                        _ => (),
                    }
                }

                for param in entry.params.iter() {
                    if let ArchivedVCardParameterValue::Text(value) = &param.value {
                        let lang = if is_text {
                            detector.detect(v.as_str(), MIN_LANGUAGE_SCORE);
                            Language::Unknown
                        } else {
                            Language::None
                        };
                        document.index_text(field.clone(), value, lang);
                    }
                }
            }
        }

        if let Some(detected_language) = detector.most_frequent_language() {
            document.set_unknown_language(detected_language);
        }

        document
    }
}
