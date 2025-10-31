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
    Email(EmailSearchField),
    Calendar(CalendarSearchField),
    Contact(ContactSearchField),
    File(FileSearchField),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchValue {
    Text { value: String, language: Language },
    Number(i64),
    Boolean(bool),
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
    pub(crate) account_id: u32,
    pub(crate) document_id: u32,
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
            account_id: 0,
            document_id: 0,
        }
    }

    pub fn with_account_id(mut self, account_id: u32) -> Self {
        self.account_id = account_id;
        self
    }

    pub fn with_document_id(mut self, document_id: u32) -> Self {
        self.document_id = document_id;
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

    pub fn index_number<N: Into<i64>>(&mut self, field: impl Into<SearchField>, value: N) {
        self.fields
            .insert(field.into(), SearchValue::Number(value.into()));
    }

    pub fn has_field(&self, field: &SearchField) -> bool {
        self.fields.contains_key(field)
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

impl From<u64> for SearchValue {
    fn from(value: u64) -> Self {
        SearchValue::Number(value as i64)
    }
}

impl From<i64> for SearchValue {
    fn from(value: i64) -> Self {
        SearchValue::Number(value)
    }
}

impl From<u32> for SearchValue {
    fn from(value: u32) -> Self {
        SearchValue::Number(value as i64)
    }
}

impl From<i32> for SearchValue {
    fn from(value: i32) -> Self {
        SearchValue::Number(value as i64)
    }
}

impl From<usize> for SearchValue {
    fn from(value: usize) -> Self {
        SearchValue::Number(value as i64)
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
