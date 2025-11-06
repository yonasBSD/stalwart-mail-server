/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, Serialize, U64_LEN,
    backend::MAX_TOKEN_LENGTH,
    search::*,
    write::{
        Archiver, BatchBuilder, MergeResult, Params, SEARCH_INDEX_MAX_FIELD_LEN, SearchIndexClass,
        SearchIndexField, SearchIndexId, SearchIndexType, ValueClass,
    },
};
use nlp::{language::stemmer::Stemmer, tokenizers::word::WordTokenizer};
use roaring::RoaringTreemap;
use utils::cheeky_hash::{CheekyBTreeMap, CheekyHash};

#[derive(Debug, PartialEq, Eq, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub(crate) struct TermIndex {
    terms: Vec<Term>,
    fields: Vec<SearchIndexField>,
}

#[derive(Debug, PartialEq, Eq, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub(crate) struct Term {
    hash: CheekyHash,
    fields: u32,
}

pub(crate) struct TermIndexBuilder {
    pub(crate) index: TermIndex,
    pub(crate) id: SearchIndexId,
}

impl TermIndexBuilder {
    pub fn build(document: IndexDocument) -> Self {
        let mut terms: CheekyBTreeMap<u32> = CheekyBTreeMap::new();
        let mut fields: Vec<SearchIndexField> = Vec::new();
        let mut account_id = None;
        let mut document_id = None;
        let mut id = None;

        for (field, value) in document.fields {
            match field {
                SearchField::Id => {
                    if let SearchValue::Uint(v) = value {
                        id = Some(v);
                    }
                    continue;
                }
                SearchField::AccountId => {
                    if let SearchValue::Uint(v) = value {
                        account_id = Some(v);
                    }
                    continue;
                }
                SearchField::DocumentId => {
                    if let SearchValue::Uint(v) = value {
                        document_id = Some(v);
                    }
                    continue;
                }
                _ => {}
            }

            let field_id = 1 << (field.u8_id() as u32);

            let field = match value {
                SearchValue::Text { value, language } => {
                    if field.is_text() {
                        if !matches!(language, Language::Unknown | Language::None) {
                            for token in Stemmer::new(&value, language, MAX_TOKEN_LENGTH) {
                                *terms
                                    .entry(CheekyHash::new(token.word.as_bytes()))
                                    .or_default() |= field_id;

                                if let Some(stemmed_word) = token.stemmed_word {
                                    *terms
                                        .entry(CheekyHash::new(
                                            format!("{}*", stemmed_word).as_bytes(),
                                        ))
                                        .or_default() |= field_id;
                                }
                            }
                        } else {
                            for token in WordTokenizer::new(value.as_str(), MAX_TOKEN_LENGTH) {
                                *terms
                                    .entry(CheekyHash::new(token.word.as_bytes()))
                                    .or_default() |= field_id;
                            }
                        }
                    }

                    if field.is_indexed() {
                        let bytes = value.as_bytes();
                        let len = bytes.len().min(SEARCH_INDEX_MAX_FIELD_LEN);
                        let mut data = [0u8; SEARCH_INDEX_MAX_FIELD_LEN];

                        data[..len].copy_from_slice(&bytes[..len]);

                        SearchIndexField {
                            field_id: field.u8_id(),
                            len: len as u8,
                            data,
                        }
                    } else {
                        continue;
                    }
                }
                SearchValue::KeyValues(map) => {
                    for (key, value) in map {
                        *terms.entry(CheekyHash::new(key.as_bytes())).or_default() |= field_id;
                        for token in value.split_ascii_whitespace() {
                            *terms
                                .entry(CheekyHash::new(format!("{key} {token}").as_bytes()))
                                .or_default() |= field_id;
                        }
                    }

                    continue;
                }
                SearchValue::Int(v) => {
                    let mut data = [0u8; SEARCH_INDEX_MAX_FIELD_LEN];
                    data[..U64_LEN].copy_from_slice(&v.to_be_bytes());

                    SearchIndexField {
                        field_id: field.u8_id(),
                        len: U64_LEN as u8,
                        data,
                    }
                }
                SearchValue::Uint(v) => {
                    let mut data = [0u8; SEARCH_INDEX_MAX_FIELD_LEN];
                    data[..U64_LEN].copy_from_slice(&v.to_be_bytes());

                    SearchIndexField {
                        field_id: field.u8_id(),
                        len: U64_LEN as u8,
                        data,
                    }
                }
                SearchValue::Boolean(v) if v => SearchIndexField {
                    field_id: field.u8_id(),
                    len: 1,
                    data: [1u8; SEARCH_INDEX_MAX_FIELD_LEN],
                },
                _ => continue,
            };

            fields.push(field);
        }

        TermIndexBuilder {
            index: TermIndex {
                terms: terms
                    .into_iter()
                    .map(|(k, v)| Term { hash: k, fields: v })
                    .collect(),
                fields,
            },
            id: match (account_id, document_id, id) {
                (Some(account_id), Some(document_id), None) => SearchIndexId::Account {
                    account_id: account_id as u32,
                    document_id: document_id as u32,
                },
                (None, None, Some(id)) => SearchIndexId::Global { id },
                _ => {
                    debug_assert!(
                        false,
                        "Invalid combination of AccountId, DocumentId and Id fields"
                    );
                    SearchIndexId::Global { id: 0 }
                }
            },
        }
    }
}

impl TermIndex {
    pub fn write_index(
        self,
        batch: &mut BatchBuilder,
        index: SearchIndex,
        id: SearchIndexId,
    ) -> trc::Result<()> {
        let archive = Archiver::new(self);
        batch.set(
            ValueClass::SearchIndex(SearchIndexClass {
                index,
                typ: SearchIndexType::Document { id },
            }),
            archive.serialize()?,
        );

        match id {
            SearchIndexId::Account {
                account_id,
                document_id,
            } => {
                for term in archive.inner.terms {
                    batch.merge_fnc(
                        ValueClass::SearchIndex(SearchIndexClass {
                            index,
                            typ: SearchIndexType::Term {
                                account_id: Some(account_id),
                                hash: term.hash,
                            },
                        }),
                        Params::with_capacity(1).with_u64(document_id as u64),
                        |params, _, bytes| {
                            let document_id = params.u64(0) as u32;

                            if let Some(bytes) = bytes {
                                let mut bitmap = RoaringBitmap::deserialize(bytes)?;
                                if bitmap.insert(document_id) {
                                    Ok(MergeResult::Update(bitmap.serialize()?))
                                } else {
                                    Ok(MergeResult::Skip)
                                }
                            } else {
                                Ok(MergeResult::Update(
                                    RoaringBitmap::from_iter([document_id]).serialize()?,
                                ))
                            }
                        },
                    );
                }
            }
            SearchIndexId::Global { id } => {
                for term in archive.inner.terms {
                    batch.merge_fnc(
                        ValueClass::SearchIndex(SearchIndexClass {
                            index,
                            typ: SearchIndexType::Term {
                                account_id: None,
                                hash: term.hash,
                            },
                        }),
                        Params::with_capacity(1).with_u64(id),
                        |params, _, bytes| {
                            let id = params.u64(0);

                            if let Some(bytes) = bytes {
                                let mut bitmap = RoaringTreemap::deserialize(bytes)?;
                                if bitmap.insert(id) {
                                    Ok(MergeResult::Update(bitmap.serialize()?))
                                } else {
                                    Ok(MergeResult::Skip)
                                }
                            } else {
                                Ok(MergeResult::Update(
                                    RoaringTreemap::from_iter([id]).serialize()?,
                                ))
                            }
                        },
                    );
                }
            }
        }

        for field in archive.inner.fields {
            batch.set(
                ValueClass::SearchIndex(SearchIndexClass {
                    index,
                    typ: SearchIndexType::Index { id, field },
                }),
                vec![],
            );
        }

        Ok(())
    }
}

impl ArchivedTermIndex {
    pub fn has_term(&self, hash: &CheekyHash, field: &SearchField) -> bool {
        let hash = hash.as_raw_bytes();
        self.terms
            .binary_search_by(|term| term.hash.as_raw_bytes().cmp(hash))
            .is_ok_and(|idx| {
                (self.terms[idx].fields.to_native() & (1 << (field.u8_id() as u32))) != 0
            })
    }

    pub fn delete_index(&self, batch: &mut BatchBuilder, index: SearchIndex, id: SearchIndexId) {
        batch.clear(ValueClass::SearchIndex(SearchIndexClass {
            index,
            typ: SearchIndexType::Document { id },
        }));

        match id {
            SearchIndexId::Account {
                account_id,
                document_id,
            } => {
                for term in self.terms.iter() {
                    batch.merge_fnc(
                        ValueClass::SearchIndex(SearchIndexClass {
                            index,
                            typ: SearchIndexType::Term {
                                account_id: Some(account_id),
                                hash: term.hash.to_native(),
                            },
                        }),
                        Params::with_capacity(1).with_u64(document_id as u64),
                        |params, _, bytes| {
                            let document_id = params.u64(0) as u32;

                            if let Some(bytes) = bytes {
                                let mut bitmap = RoaringBitmap::deserialize(bytes)?;
                                if bitmap.remove(document_id) {
                                    if !bitmap.is_empty() {
                                        Ok(MergeResult::Update(bitmap.serialize()?))
                                    } else {
                                        Ok(MergeResult::Delete)
                                    }
                                } else {
                                    Ok(MergeResult::Skip)
                                }
                            } else {
                                Ok(MergeResult::Skip)
                            }
                        },
                    );
                }
            }
            SearchIndexId::Global { id } => {
                for term in self.terms.iter() {
                    batch.merge_fnc(
                        ValueClass::SearchIndex(SearchIndexClass {
                            index,
                            typ: SearchIndexType::Term {
                                account_id: None,
                                hash: term.hash.to_native(),
                            },
                        }),
                        Params::with_capacity(1).with_u64(id),
                        |params, _, bytes| {
                            let id = params.u64(0);

                            if let Some(bytes) = bytes {
                                let mut bitmap = RoaringTreemap::deserialize(bytes)?;
                                if bitmap.remove(id) {
                                    if !bitmap.is_empty() {
                                        Ok(MergeResult::Update(bitmap.serialize()?))
                                    } else {
                                        Ok(MergeResult::Delete)
                                    }
                                } else {
                                    Ok(MergeResult::Skip)
                                }
                            } else {
                                Ok(MergeResult::Skip)
                            }
                        },
                    );
                }
            }
        }

        for field in self.fields.iter() {
            batch.clear(ValueClass::SearchIndex(SearchIndexClass {
                index,
                typ: SearchIndexType::Index {
                    id,
                    field: SearchIndexField {
                        field_id: field.field_id,
                        len: field.len,
                        data: field.data,
                    },
                },
            }));
        }
    }
}

impl SearchIndex {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            SearchIndex::Email => 0,
            SearchIndex::Calendar => 1,
            SearchIndex::Contacts => 2,
            SearchIndex::File => 3,
            SearchIndex::Tracing => 4,
            SearchIndex::InMemory => unreachable!(),
        }
    }
}

impl SearchField {
    pub(crate) fn u8_id(&self) -> u8 {
        match self {
            SearchField::AccountId => 0,
            SearchField::DocumentId => 1,
            SearchField::Id => 2,
            SearchField::Email(field) => match field {
                EmailSearchField::From => 3,
                EmailSearchField::To => 4,
                EmailSearchField::Cc => 5,
                EmailSearchField::Bcc => 6,
                EmailSearchField::Subject => 7,
                EmailSearchField::Body => 8,
                EmailSearchField::Attachment => 9,
                EmailSearchField::ReceivedAt => 10,
                EmailSearchField::SentAt => 11,
                EmailSearchField::Size => 12,
                EmailSearchField::HasAttachment => 13,
                EmailSearchField::Headers => 14,
            },
            SearchField::Calendar(field) => match field {
                CalendarSearchField::Title => 3,
                CalendarSearchField::Description => 4,
                CalendarSearchField::Location => 5,
                CalendarSearchField::Owner => 6,
                CalendarSearchField::Attendee => 7,
                CalendarSearchField::Start => 8,
                CalendarSearchField::Uid => 9,
            },
            SearchField::Contact(field) => match field {
                ContactSearchField::Member => 3,
                ContactSearchField::Kind => 4,
                ContactSearchField::Name => 5,
                ContactSearchField::Nickname => 6,
                ContactSearchField::Organization => 7,
                ContactSearchField::Email => 8,
                ContactSearchField::Phone => 9,
                ContactSearchField::OnlineService => 10,
                ContactSearchField::Address => 11,
                ContactSearchField::Note => 12,
                ContactSearchField::Uid => 13,
            },
            SearchField::File(field) => match field {
                FileSearchField::Name => 3,
                FileSearchField::Content => 4,
            },
            SearchField::Tracing(field) => match field {
                TracingSearchField::EventType => 3,
                TracingSearchField::QueueId => 4,
                TracingSearchField::Keywords => 5,
            },
        }
    }
}
