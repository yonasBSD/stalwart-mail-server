/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod index;
pub mod local;
pub mod query;

use ahash::AHashMap;
use nlp::language::Language;
use roaring::RoaringBitmap;
use std::{borrow::Cow, collections::hash_map::Entry};

use crate::write::SearchIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchOperator {
    LowerThan,
    LowerEqualThan,
    GreaterThan,
    GreaterEqualThan,
    Equal,
    Contains,
    Exists,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SearchField {
    AccountId,
    DocumentId,
    Id,
    Email(EmailSearchField),
    Calendar(CalendarSearchField),
    Contact(ContactSearchField),
    File(FileSearchField),
    Tracing(TracingSearchField),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EmailSearchField {
    From,
    To,
    Cc,
    Bcc,
    Subject,
    Body,
    Attachment,
    ReceivedAt,
    SentAt,
    Size,
    HasAttachment,
    Header(Cow<'static, str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CalendarSearchField {
    Title,
    Description,
    Location,
    Owner,
    Attendee,
    Start,
    Uid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContactSearchField {
    Created,
    Member,
    Kind,
    Name,
    Nickname,
    Organization,
    Email,
    Phone,
    OnlineService,
    Address,
    Note,
    Uid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileSearchField {
    Name,
    Content,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TracingSearchField {
    EventType,
    QueueId,
    Address,
    RemoteIp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchValue {
    Text { value: String, language: Language },
    Int(i64),
    Uint(u64),
    Boolean(bool),
    Keywords(Vec<SearchValue>),
}

pub trait SearchDocumentId: Sized {
    fn from_u32(id: u32) -> Self;
    fn from_u64(id: u64) -> Self;
    fn field(&self) -> SearchField;
}

#[derive(Debug)]
pub struct SearchQuery {
    index: SearchIndex,
    filters: Vec<SearchFilter>,
    comparators: Vec<SearchComparator>,
    mask: RoaringBitmap,
}

#[derive(Debug)]
pub enum SearchFilter {
    Operator {
        field: SearchField,
        op: SearchOperator,
        value: SearchValue,
    },
    DocumentSet(RoaringBitmap),
    And,
    Or,
    Not,
    End,
}

#[derive(Debug)]
pub enum SearchComparator {
    Field { field: SearchField, ascending: bool },
    DocumentSet { set: RoaringBitmap, ascending: bool },
    SortedList { list: Vec<u32>, ascending: bool },
}

#[derive(Debug)]
pub struct IndexDocument {
    pub(crate) fields: AHashMap<SearchField, SearchValue>,
    pub(crate) default_language: Language,
}

impl SearchFilter {
    pub fn cond(
        field: impl Into<SearchField>,
        op: SearchOperator,
        value: impl Into<SearchValue>,
    ) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op,
            value: value.into(),
        }
    }

    pub fn exists(field: impl Into<SearchField>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::Exists,
            value: SearchValue::Boolean(true),
        }
    }

    pub fn eq(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::Equal,
            value: value.into(),
        }
    }

    pub fn lt(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::LowerThan,
            value: value.into(),
        }
    }

    pub fn le(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::LowerEqualThan,
            value: value.into(),
        }
    }

    pub fn gt(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::GreaterThan,
            value: value.into(),
        }
    }

    pub fn ge(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::GreaterEqualThan,
            value: value.into(),
        }
    }

    pub fn has_text_detect(
        field: impl Into<SearchField>,
        text: impl Into<String>,
        default_language: Language,
    ) -> Self {
        let (text, language) = Language::detect(text.into(), default_language);
        Self::has_text(field, text, language)
    }

    pub fn has_text(
        field: impl Into<SearchField>,
        text: impl Into<String>,
        language: Language,
    ) -> Self {
        let text = text.into();
        let (is_exact, text) = if let Some(text) = text
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .or_else(|| text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')))
        {
            (true, text.to_string())
        } else {
            (false, text)
        };

        if !matches!(language, Language::None) && is_exact {
            SearchFilter::Operator {
                field: field.into(),
                op: SearchOperator::Equal,
                value: SearchValue::Text {
                    value: text,
                    language,
                },
            }
        } else {
            SearchFilter::Operator {
                field: field.into(),
                op: SearchOperator::Contains,
                value: SearchValue::Text {
                    value: text,
                    language,
                },
            }
        }
    }

    #[inline(always)]
    pub fn has_english_text(field: impl Into<SearchField>, text: impl Into<String>) -> Self {
        Self::has_text(field, text, Language::English)
    }

    #[inline(always)]
    pub fn has_unknown_text(field: impl Into<SearchField>, text: impl Into<String>) -> Self {
        Self::has_text(field, text, Language::Unknown)
    }

    pub fn is_in_set(set: RoaringBitmap) -> Self {
        SearchFilter::DocumentSet(set)
    }
}

impl SearchComparator {
    pub fn field(field: impl Into<SearchField>, ascending: bool) -> Self {
        Self::Field {
            field: field.into(),
            ascending,
        }
    }

    pub fn set(set: RoaringBitmap, ascending: bool) -> Self {
        Self::DocumentSet { set, ascending }
    }

    pub fn sorted_list(list: Vec<u32>, ascending: bool) -> Self {
        Self::SortedList { list, ascending }
    }

    pub fn ascending(field: impl Into<SearchField>) -> Self {
        Self::Field {
            field: field.into(),
            ascending: true,
        }
    }

    pub fn descending(field: impl Into<SearchField>) -> Self {
        Self::Field {
            field: field.into(),
            ascending: false,
        }
    }
}

impl IndexDocument {
    pub fn with_default_language(default_language: Language) -> Self {
        Self {
            fields: Default::default(),
            default_language,
        }
    }

    pub fn with_account_id(mut self, account_id: u32) -> Self {
        self.fields
            .insert(SearchField::AccountId, SearchValue::Uint(account_id as u64));
        self
    }

    pub fn with_document_id(mut self, document_id: u32) -> Self {
        self.fields.insert(
            SearchField::DocumentId,
            SearchValue::Uint(document_id as u64),
        );
        self
    }

    pub fn with_id(mut self, id: u64) -> Self {
        self.fields.insert(SearchField::Id, SearchValue::Uint(id));
        self
    }

    pub fn index_text(&mut self, field: impl Into<SearchField>, value: &str, language: Language) {
        match self.fields.entry(field.into()) {
            Entry::Occupied(mut entry) => {
                if let SearchValue::Text {
                    value: existing_value,
                    ..
                } = entry.get_mut()
                {
                    existing_value.push(' ');
                    existing_value.push_str(value);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(SearchValue::Text {
                    value: value.to_string(),
                    language,
                });
            }
        }
    }

    pub fn index_bool(&mut self, field: impl Into<SearchField>, value: bool) {
        self.fields
            .insert(field.into(), SearchValue::Boolean(value));
    }

    pub fn index_integer<N: Into<i64>>(&mut self, field: impl Into<SearchField>, value: N) {
        self.fields
            .insert(field.into(), SearchValue::Int(value.into()));
    }

    pub fn index_unsigned<N: Into<u64>>(&mut self, field: impl Into<SearchField>, value: N) {
        self.fields
            .insert(field.into(), SearchValue::Uint(value.into()));
    }

    pub fn insert_keyword(
        &mut self,
        field: impl Into<SearchField>,
        keyword: impl Into<SearchValue>,
    ) {
        let search_field = field.into();

        match self.fields.entry(search_field) {
            Entry::Occupied(mut entry) => {
                if let SearchValue::Keywords(existing_keywords) = entry.get_mut() {
                    existing_keywords.push(keyword.into());
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(SearchValue::Keywords(vec![keyword.into()]));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn has_field(&self, field: &SearchField) -> bool {
        self.fields.contains_key(field)
    }
}

impl SearchQuery {
    pub fn new(index: SearchIndex) -> Self {
        Self {
            index,
            filters: Vec::new(),
            comparators: Vec::new(),
            mask: RoaringBitmap::new(),
        }
    }

    pub fn with_filters(mut self, filters: Vec<SearchFilter>) -> Self {
        if self.filters.is_empty() {
            self.filters = filters;
        } else {
            self.filters.extend(filters);
        }
        self
    }

    pub fn with_comparators(mut self, comparators: Vec<SearchComparator>) -> Self {
        if self.comparators.is_empty() {
            self.comparators = comparators;
        } else {
            self.comparators.extend(comparators);
        }
        self
    }

    pub fn with_filter(mut self, filter: SearchFilter) -> Self {
        self.filters.push(filter);
        self
    }

    pub fn add_filter(&mut self, filter: SearchFilter) -> &mut Self {
        self.filters.push(filter);
        self
    }

    pub fn with_comparator(mut self, comparator: SearchComparator) -> Self {
        self.comparators.push(comparator);
        self
    }

    pub fn with_mask(mut self, mask: RoaringBitmap) -> Self {
        self.mask = mask;
        self
    }

    pub fn with_account_id(mut self, account_id: u32) -> Self {
        self.filters.push(SearchFilter::cond(
            SearchField::AccountId,
            SearchOperator::Equal,
            SearchValue::Uint(account_id as u64),
        ));
        self
    }

    pub fn execute(&self) -> RoaringBitmap {
        let todo = "implement search execution logic";
        todo!()
    }
}

impl From<EmailSearchField> for SearchField {
    fn from(field: EmailSearchField) -> Self {
        SearchField::Email(field)
    }
}

impl From<CalendarSearchField> for SearchField {
    fn from(field: CalendarSearchField) -> Self {
        SearchField::Calendar(field)
    }
}

impl From<ContactSearchField> for SearchField {
    fn from(field: ContactSearchField) -> Self {
        SearchField::Contact(field)
    }
}

impl From<FileSearchField> for SearchField {
    fn from(field: FileSearchField) -> Self {
        SearchField::File(field)
    }
}

impl From<TracingSearchField> for SearchField {
    fn from(field: TracingSearchField) -> Self {
        SearchField::Tracing(field)
    }
}

impl From<u64> for SearchValue {
    fn from(value: u64) -> Self {
        SearchValue::Uint(value)
    }
}

impl From<i64> for SearchValue {
    fn from(value: i64) -> Self {
        SearchValue::Int(value)
    }
}

impl From<u32> for SearchValue {
    fn from(value: u32) -> Self {
        SearchValue::Uint(value as u64)
    }
}

impl From<i32> for SearchValue {
    fn from(value: i32) -> Self {
        SearchValue::Int(value as i64)
    }
}

impl From<usize> for SearchValue {
    fn from(value: usize) -> Self {
        SearchValue::Uint(value as u64)
    }
}

impl From<bool> for SearchValue {
    fn from(value: bool) -> Self {
        SearchValue::Boolean(value)
    }
}

impl From<String> for SearchValue {
    fn from(value: String) -> Self {
        SearchValue::Text {
            value,
            language: Language::None,
        }
    }
}

impl SearchDocumentId for u32 {
    fn from_u32(id: u32) -> Self {
        id
    }

    fn from_u64(id: u64) -> Self {
        id as u32
    }

    fn field(&self) -> SearchField {
        SearchField::DocumentId
    }
}

impl SearchDocumentId for u64 {
    fn from_u32(id: u32) -> Self {
        id as u64
    }

    fn from_u64(id: u64) -> Self {
        id
    }

    fn field(&self) -> SearchField {
        SearchField::Id
    }
}
