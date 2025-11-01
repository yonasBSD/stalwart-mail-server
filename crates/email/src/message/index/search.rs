/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::{MAX_MESSAGE_PARTS, extractors::VisitTextArchived},
    metadata::{ArchivedMessageMetadata, ArchivedMetadataPartType, DecodedPartContent},
};
use mail_parser::{
    ArchivedHeaderName, ArchivedHeaderValue, DateTime, HeaderName, core::rkyv::ArchivedGetHeader,
    decoders::html::html_to_text,
};
use nlp::language::Language;
use std::borrow::Cow;
use store::{
    ahash::AHashSet,
    search::{EmailSearchField, IndexDocument, SearchField},
};

impl ArchivedMessageMetadata {
    pub fn index_document(
        &self,
        raw_message: &[u8],
        index_headers: &AHashSet<HeaderName<'static>>,
    ) -> IndexDocument {
        let mut language = Language::Unknown;
        let message_contents = &self.contents[0];
        let mut document = IndexDocument::with_default_language(language);

        document.index_unsigned(EmailSearchField::ReceivedAt, self.received_at.to_native());
        document.index_unsigned(EmailSearchField::Size, self.size.to_native());

        for (part_id, part) in message_contents
            .parts
            .iter()
            .take(MAX_MESSAGE_PARTS)
            .enumerate()
        {
            let part_language = part.language().unwrap_or(language);
            if part_id == 0 {
                language = part_language;

                for header in part.headers.iter().rev() {
                    let header_name = HeaderName::from(&header.name);
                    if !index_headers.is_empty() && !index_headers.contains(&header_name) {
                        continue;
                    }
                    let header_name = match header_name {
                        HeaderName::Other(name) => Cow::Owned(name.into_owned()),
                        _ => Cow::Borrowed(header_name.as_static_str()),
                    };

                    match &header.name {
                        ArchivedHeaderName::From => {
                            header.value.visit_addresses(|_, value| {
                                document.index_text(
                                    EmailSearchField::From,
                                    value,
                                    Language::Unknown,
                                );
                            });
                        }
                        ArchivedHeaderName::To => {
                            header.value.visit_addresses(|_, value| {
                                document.index_text(EmailSearchField::To, value, Language::Unknown);
                            });
                        }
                        ArchivedHeaderName::Cc => {
                            header.value.visit_addresses(|_, value| {
                                document.index_text(EmailSearchField::Cc, value, Language::Unknown);
                            });
                        }
                        ArchivedHeaderName::Bcc => {
                            header.value.visit_addresses(|_, value| {
                                document.index_text(
                                    EmailSearchField::Bcc,
                                    value,
                                    Language::Unknown,
                                );
                            });
                        }
                        ArchivedHeaderName::Subject => {
                            if let Some(subject) = header.value.as_text() {
                                document.index_text(
                                    EmailSearchField::Subject,
                                    subject,
                                    part_language,
                                );
                            }
                        }
                        ArchivedHeaderName::Date => {
                            if let Some(date) = header.value.as_datetime() {
                                document.index_integer(
                                    EmailSearchField::SentAt,
                                    DateTime::from(date).to_timestamp(),
                                );
                            }
                        }
                        _ => {
                            header.value.visit_text(|text| {
                                document.index_text(
                                    EmailSearchField::Header(header_name.clone()),
                                    text,
                                    Language::Unknown,
                                );
                            });
                        }
                    }
                }
            }

            let part_id = part_id as u16;
            match &part.body {
                ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                    let text = match (part.decode_contents(raw_message), &part.body) {
                        (DecodedPartContent::Text(text), ArchivedMetadataPartType::Text) => text,
                        (DecodedPartContent::Text(html), ArchivedMetadataPartType::Html) => {
                            html_to_text(html.as_ref()).into()
                        }
                        _ => unreachable!(),
                    };

                    if message_contents.is_html_part(part_id)
                        || message_contents.is_text_part(part_id)
                    {
                        document.index_text(EmailSearchField::Body, text.as_ref(), part_language);
                    } else {
                        document.index_text(
                            EmailSearchField::Attachment,
                            text.as_ref(),
                            part_language,
                        );
                    }
                }
                ArchivedMetadataPartType::Message(nested_message_id) => {
                    let nested_message = self.message_id(*nested_message_id);
                    let nested_message_language = nested_message
                        .root_part()
                        .language()
                        .unwrap_or(Language::Unknown);
                    if let Some(ArchivedHeaderValue::Text(subject)) = nested_message
                        .root_part()
                        .headers
                        .header_value(&ArchivedHeaderName::Subject)
                    {
                        document.index_text(
                            EmailSearchField::Attachment,
                            subject.as_ref(),
                            nested_message_language,
                        );
                    }

                    for sub_part in nested_message.parts.iter().take(MAX_MESSAGE_PARTS) {
                        let language = sub_part.language().unwrap_or(nested_message_language);
                        match &sub_part.body {
                            ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                                let text =
                                    match (sub_part.decode_contents(raw_message), &sub_part.body) {
                                        (
                                            DecodedPartContent::Text(text),
                                            ArchivedMetadataPartType::Text,
                                        ) => text,
                                        (
                                            DecodedPartContent::Text(html),
                                            ArchivedMetadataPartType::Html,
                                        ) => html_to_text(html.as_ref()).into(),
                                        _ => unreachable!(),
                                    };
                                document.index_text(
                                    EmailSearchField::Attachment,
                                    text.as_ref(),
                                    language,
                                );
                            }
                            _ => (),
                        }
                    }
                }
                _ => {}
            }
        }

        let has_attachment = document.has_field(&SearchField::Email(EmailSearchField::Attachment));

        document.index_bool(EmailSearchField::HasAttachment, has_attachment);

        document
    }
}
