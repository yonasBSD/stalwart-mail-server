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
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};
use utils::map::vec_map::VecMap;

use crate::write::SearchIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchOperator {
    LowerThan,
    LowerEqualThan,
    GreaterThan,
    GreaterEqualThan,
    Equal,
    Contains,
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
    Headers,
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
    Keywords,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchValue {
    Text { value: String, language: Language },
    KeyValues(VecMap<String, String>),
    Int(i64),
    Uint(u64),
    Boolean(bool),
}

pub trait SearchDocumentId: Sized {
    fn from_u32(id: u32) -> Self;
    fn from_u64(id: u64) -> Self;
    fn field() -> SearchField;
}

#[derive(Debug)]
pub struct SearchQuery {
    pub(crate) index: SearchIndex,
    pub(crate) filters: Vec<SearchFilter>,
    pub(crate) comparators: Vec<SearchComparator>,
    pub(crate) mask: RoaringBitmap,
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
    Field {
        field: SearchField,
        ascending: bool,
    },
    DocumentSet {
        set: RoaringBitmap,
        ascending: bool,
    },
    SortedSet {
        set: AHashMap<u32, u32>,
        ascending: bool,
    },
}

#[derive(Debug)]
pub struct IndexDocument {
    pub(crate) index: SearchIndex,
    pub(crate) fields: AHashMap<SearchField, SearchValue>,
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

    pub fn sorted_set(set: AHashMap<u32, u32>, ascending: bool) -> Self {
        Self::SortedSet { set, ascending }
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
    pub fn new(index: SearchIndex) -> Self {
        Self {
            fields: Default::default(),
            index,
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

    pub fn insert_key_value(
        &mut self,
        field: impl Into<SearchField>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        let search_field = field.into();

        match self.fields.entry(search_field) {
            Entry::Occupied(mut entry) => {
                if let SearchValue::KeyValues(existing_key_values) = entry.get_mut() {
                    existing_key_values.append(key.into(), value.into());
                }
            }
            Entry::Vacant(entry) => {
                let mut new_key_values = VecMap::new();
                new_key_values.append(key.into(), value.into());
                entry.insert(SearchValue::KeyValues(new_key_values));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn has_field(&self, field: &SearchField) -> bool {
        self.fields.contains_key(field)
    }

    pub fn set_unknown_language(&mut self, lang: Language) {
        for value in self.fields.values_mut() {
            if let SearchValue::Text { language, .. } = value
                && language.is_unknown()
            {
                *language = lang;
            }
        }
    }
}

struct State {
    pub op: SearchFilter,
    pub bm: Option<RoaringBitmap>,
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

    pub fn filter(self) -> QueryResults {
        if self.filters.is_empty() {
            return QueryResults {
                results: self.mask,
                comparators: self.comparators,
            };
        }
        let mut state: State = State {
            op: SearchFilter::And,
            bm: None,
        };
        let mut stack = Vec::new();
        let mut filters = self.filters.into_iter().peekable();
        let mask = self.mask;

        while let Some(filter) = filters.next() {
            let mut result = match filter {
                SearchFilter::DocumentSet(set) => Some(set),
                op @ (SearchFilter::And | SearchFilter::Or | SearchFilter::Not) => {
                    stack.push(state);
                    state = State { op, bm: None };
                    continue;
                }
                SearchFilter::End => {
                    if let Some(prev_state) = stack.pop() {
                        let bm = state.bm;
                        state = prev_state;
                        bm
                    } else {
                        break;
                    }
                }
                SearchFilter::Operator { .. } => {
                    continue;
                }
            };

            // Apply logical operation
            if let Some(dest) = &mut state.bm {
                match state.op {
                    SearchFilter::And => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    SearchFilter::Or => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    SearchFilter::Not => {
                        if let Some(mut result) = result {
                            result.bitxor_assign(&mask);
                            dest.bitand_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if let Some(ref mut result_) = result {
                if let SearchFilter::Not = state.op {
                    result_.bitxor_assign(&mask);
                }
                state.bm = result;
            } else if let SearchFilter::Not = state.op {
                state.bm = Some(mask.clone());
            } else {
                state.bm = Some(RoaringBitmap::new());
            }

            // And short-circuit
            if matches!(state.op, SearchFilter::And) && state.bm.as_ref().unwrap().is_empty() {
                while let Some(filter) = filters.peek() {
                    if matches!(filter, SearchFilter::End) {
                        break;
                    } else {
                        filters.next();
                    }
                }
            }
        }

        // AND with mask
        let mut results = state.bm.unwrap_or_default();
        results.bitand_assign(&mask);
        QueryResults {
            results,
            comparators: self.comparators,
        }
    }
}

pub struct QueryResults {
    results: RoaringBitmap,
    comparators: Vec<SearchComparator>,
}

impl QueryResults {
    pub fn results(&self) -> &RoaringBitmap {
        &self.results
    }

    pub fn update_results(&mut self, results: RoaringBitmap) {
        self.results = results;
    }

    pub fn into_bitmap(self) -> RoaringBitmap {
        self.results
    }

    pub fn into_sorted(self) -> Vec<u32> {
        let comparators = self.comparators;
        let mut results = self.results.into_iter().collect::<Vec<u32>>();

        if !results.is_empty() && !comparators.is_empty() {
            results.sort_by(|a, b| {
                for comparator in &comparators {
                    let (a, b, is_ascending) = match comparator {
                        SearchComparator::DocumentSet { set, ascending } => {
                            (set.contains(*a) as u32, set.contains(*b) as u32, *ascending)
                        }
                        SearchComparator::SortedSet { set, ascending } => (
                            *set.get(a).unwrap_or(&u32::MAX),
                            *set.get(b).unwrap_or(&u32::MAX),
                            *ascending,
                        ),
                        SearchComparator::Field { .. } => continue,
                    };

                    let ordering = if is_ascending {
                        a.cmp(&b).reverse()
                    } else {
                        a.cmp(&b)
                    };

                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
                Ordering::Equal
            });
        }

        results
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

    fn field() -> SearchField {
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

    fn field() -> SearchField {
        SearchField::Id
    }
}

impl SearchIndex {
    pub fn all_fields(&self) -> &[SearchField] {
        match self {
            SearchIndex::Email => EmailSearchField::all_fields(),
            SearchIndex::Calendar => CalendarSearchField::all_fields(),
            SearchIndex::Contacts => ContactSearchField::all_fields(),
            SearchIndex::File => FileSearchField::all_fields(),
            SearchIndex::Tracing => TracingSearchField::all_fields(),
            SearchIndex::InMemory => unreachable!(),
        }
    }

    pub fn primary_keys(&self) -> &'static [SearchField] {
        match self {
            SearchIndex::Email => EmailSearchField::primary_keys(),
            SearchIndex::Calendar => CalendarSearchField::primary_keys(),
            SearchIndex::Contacts => ContactSearchField::primary_keys(),
            SearchIndex::File => FileSearchField::primary_keys(),
            SearchIndex::Tracing => TracingSearchField::primary_keys(),
            SearchIndex::InMemory => unreachable!(),
        }
    }
}

pub trait SearchableField: Sized {
    fn index() -> SearchIndex;
    fn primary_keys() -> &'static [SearchField];
    fn all_fields() -> &'static [SearchField];
    fn is_indexed(&self) -> bool;
    fn is_text(&self) -> bool;
}

impl SearchableField for EmailSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Email
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Email(EmailSearchField::From),
            SearchField::Email(EmailSearchField::To),
            SearchField::Email(EmailSearchField::Cc),
            SearchField::Email(EmailSearchField::Bcc),
            SearchField::Email(EmailSearchField::Subject),
            SearchField::Email(EmailSearchField::Body),
            SearchField::Email(EmailSearchField::Attachment),
            SearchField::Email(EmailSearchField::ReceivedAt),
            SearchField::Email(EmailSearchField::SentAt),
            SearchField::Email(EmailSearchField::Size),
            SearchField::Email(EmailSearchField::HasAttachment),
            SearchField::Email(EmailSearchField::Headers),
        ]
    }

    fn is_indexed(&self) -> bool {
        matches!(
            self,
            EmailSearchField::From
                | EmailSearchField::To
                | EmailSearchField::Subject
                | EmailSearchField::ReceivedAt
                | EmailSearchField::Size
                | EmailSearchField::HasAttachment,
        )
    }

    fn is_text(&self) -> bool {
        matches!(
            self,
            EmailSearchField::From
                | EmailSearchField::To
                | EmailSearchField::Cc
                | EmailSearchField::Bcc
                | EmailSearchField::Subject
                | EmailSearchField::Body
                | EmailSearchField::Attachment,
        )
    }
}

impl SearchableField for CalendarSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Calendar
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Calendar(CalendarSearchField::Title),
            SearchField::Calendar(CalendarSearchField::Description),
            SearchField::Calendar(CalendarSearchField::Location),
            SearchField::Calendar(CalendarSearchField::Owner),
            SearchField::Calendar(CalendarSearchField::Attendee),
            SearchField::Calendar(CalendarSearchField::Start),
            SearchField::Calendar(CalendarSearchField::Uid),
        ]
    }

    fn is_indexed(&self) -> bool {
        matches!(self, CalendarSearchField::Start | CalendarSearchField::Uid)
    }

    fn is_text(&self) -> bool {
        matches!(
            self,
            CalendarSearchField::Title
                | CalendarSearchField::Description
                | CalendarSearchField::Location
                | CalendarSearchField::Owner
                | CalendarSearchField::Attendee
        )
    }
}

impl SearchableField for ContactSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Contacts
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Contact(ContactSearchField::Member),
            SearchField::Contact(ContactSearchField::Kind),
            SearchField::Contact(ContactSearchField::Name),
            SearchField::Contact(ContactSearchField::Nickname),
            SearchField::Contact(ContactSearchField::Organization),
            SearchField::Contact(ContactSearchField::Email),
            SearchField::Contact(ContactSearchField::Phone),
            SearchField::Contact(ContactSearchField::OnlineService),
            SearchField::Contact(ContactSearchField::Address),
            SearchField::Contact(ContactSearchField::Note),
            SearchField::Contact(ContactSearchField::Uid),
        ]
    }

    fn is_indexed(&self) -> bool {
        matches!(self, ContactSearchField::Uid | ContactSearchField::Kind)
    }

    fn is_text(&self) -> bool {
        matches!(
            self,
            ContactSearchField::Name
                | ContactSearchField::Nickname
                | ContactSearchField::Organization
                | ContactSearchField::Email
                | ContactSearchField::Phone
                | ContactSearchField::OnlineService
                | ContactSearchField::Address
                | ContactSearchField::Note
        )
    }
}

impl SearchableField for FileSearchField {
    fn index() -> SearchIndex {
        SearchIndex::File
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::AccountId, SearchField::DocumentId]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::File(FileSearchField::Name),
            SearchField::File(FileSearchField::Content),
        ]
    }

    fn is_indexed(&self) -> bool {
        false
    }

    fn is_text(&self) -> bool {
        true
    }
}

impl SearchableField for TracingSearchField {
    fn index() -> SearchIndex {
        SearchIndex::Tracing
    }

    fn primary_keys() -> &'static [SearchField] {
        &[SearchField::Id]
    }

    fn all_fields() -> &'static [SearchField] {
        &[
            SearchField::Tracing(TracingSearchField::EventType),
            SearchField::Tracing(TracingSearchField::QueueId),
            SearchField::Tracing(TracingSearchField::Keywords),
        ]
    }

    fn is_indexed(&self) -> bool {
        matches!(
            self,
            TracingSearchField::QueueId | TracingSearchField::EventType
        )
    }

    fn is_text(&self) -> bool {
        matches!(self, TracingSearchField::Keywords)
    }
}

impl SearchField {
    pub(crate) fn is_indexed(&self) -> bool {
        match self {
            SearchField::Email(field) => field.is_indexed(),
            SearchField::Calendar(field) => field.is_indexed(),
            SearchField::Contact(field) => field.is_indexed(),
            SearchField::File(field) => field.is_indexed(),
            SearchField::Tracing(field) => field.is_indexed(),
            SearchField::AccountId | SearchField::DocumentId | SearchField::Id => false,
        }
    }

    pub(crate) fn is_text(&self) -> bool {
        match self {
            SearchField::Email(field) => field.is_text(),
            SearchField::Calendar(field) => field.is_text(),
            SearchField::Contact(field) => field.is_text(),
            SearchField::File(field) => field.is_text(),
            SearchField::Tracing(field) => field.is_text(),
            SearchField::AccountId | SearchField::DocumentId | SearchField::Id => false,
        }
    }

    pub(crate) fn is_json(&self) -> bool {
        matches!(self, SearchField::Email(EmailSearchField::Headers))
    }
}
