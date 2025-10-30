/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod index;
pub mod local;
pub mod query;

use nlp::language::Language;
use roaring::RoaringBitmap;
use std::borrow::Cow;
use types::collection::Collection;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchField {
    Email(EmailSearchField),
    Calendar(CalendarSearchField),
    Contact(ContactSearchField),
    File(FileSearchField),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarSearchField {
    Summary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactSearchField {
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub(crate) collection: Collection,
    pub(crate) document_id: u32,
    pub(crate) fields: Vec<IndexField>,
    pub(crate) default_language: Language,
}

#[derive(Debug)]
pub struct IndexField {
    pub(crate) field: SearchField,
    pub(crate) value: SearchValue,
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

    pub fn has_english_text(field: impl Into<SearchField>, text: impl Into<String>) -> Self {
        Self::has_text(field, text, Language::English)
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
            fields: vec![],
            default_language,
            account_id: 0,
            document_id: 0,
            collection: Collection::None,
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

    pub fn with_collection(mut self, collection: Collection) -> Self {
        self.collection = collection;
        self
    }

    pub fn index(&mut self, field: impl Into<SearchField>, value: impl Into<SearchValue>) {
        self.fields.push(IndexField {
            field: field.into(),
            value: value.into(),
        });
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
