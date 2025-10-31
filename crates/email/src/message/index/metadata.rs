/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::{IndexMessage, MAX_MESSAGE_PARTS, PREVIEW_LENGTH},
    metadata::{
        ArchivedMessageMetadata, ArchivedMessageMetadataPart, MessageData, MessageMetadata,
        MessageMetadataPart,
    },
};
use common::storage::index::ObjectIndexBuilder;
use mail_parser::{decoders::html::html_to_text, parsers::preview::preview_text};
use store::{
    Serialize, SerializeInfallible,
    write::{Archiver, BatchBuilder, BlobOp, DirectoryClass, IndexPropertyClass, ValueClass},
};
use trc::AddContext;
use types::{blob_hash::BlobHash, field::EmailField};

impl MessageMetadata {
    #[inline(always)]
    pub fn root_part(&self) -> &MessageMetadataPart {
        &self.contents[0].parts[0]
    }

    pub fn index(
        self,
        batch: &mut BatchBuilder,
        account_id: u32,
        tenant_id: Option<u32>,
        set: bool,
    ) -> trc::Result<()> {
        if set {
            // Serialize metadata
            batch.set(
                ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: EmailField::ReceivedToSize.into(),
                    value: self.received_at,
                }),
                self.size.serialize(),
            );
        } else {
            // Delete metadata
            batch
                .clear(EmailField::Metadata)
                .clear(ValueClass::IndexProperty(IndexPropertyClass::Integer {
                    property: EmailField::ReceivedToSize.into(),
                    value: self.received_at,
                }));
        }

        // Index properties
        let quota = if set {
            self.size as i64
        } else {
            -(self.size as i64)
        };
        batch.add(DirectoryClass::UsedQuota(account_id), quota);
        if let Some(tenant_id) = tenant_id {
            batch.add(DirectoryClass::UsedQuota(tenant_id), quota);
        }

        // Link blob
        if set {
            batch.set(
                BlobOp::Link {
                    hash: self.blob_hash.clone(),
                },
                Vec::new(),
            );
        } else {
            batch.clear(BlobOp::Link {
                hash: self.blob_hash.clone(),
            });
        }

        if set {
            batch.set(EmailField::Metadata, Archiver::new(self).serialize()?);
        }

        Ok(())
    }
}

impl ArchivedMessageMetadata {
    #[inline(always)]
    pub fn root_part(&self) -> &ArchivedMessageMetadataPart {
        &self.contents[0].parts[0]
    }

    pub fn unindex(&self, batch: &mut BatchBuilder, account_id: u32, tenant_id: Option<u32>) {
        // Delete metadata
        batch
            .clear(EmailField::Metadata)
            .clear(ValueClass::IndexProperty(IndexPropertyClass::Integer {
                property: EmailField::ReceivedToSize.into(),
                value: self.received_at.to_native(),
            }));

        // Index properties
        let quota = -(u32::from(self.size) as i64);
        batch.add(DirectoryClass::UsedQuota(account_id), quota);
        if let Some(tenant_id) = tenant_id {
            batch.add(DirectoryClass::UsedQuota(tenant_id), quota);
        }

        // Unlink blob
        batch.clear(BlobOp::Link {
            hash: BlobHash::from(&self.blob_hash),
        });
    }
}

impl IndexMessage for BatchBuilder {
    fn index_message(
        &mut self,
        account_id: u32,
        tenant_id: Option<u32>,
        message: mail_parser::Message<'_>,
        blob_hash: BlobHash,
        data: MessageData,
        received_at: u64,
    ) -> trc::Result<&mut Self> {
        // Index size
        self.set(
            ValueClass::IndexProperty(IndexPropertyClass::Integer {
                property: EmailField::ReceivedToSize.into(),
                value: received_at,
            }),
            (message.raw_message.len() as u32).serialize(),
        )
        .add(
            DirectoryClass::UsedQuota(account_id),
            message.raw_message.len() as i64,
        );
        if let Some(tenant_id) = tenant_id {
            self.add(
                DirectoryClass::UsedQuota(tenant_id),
                message.raw_message.len() as i64,
            );
        }

        let mut has_attachments = false;
        let mut preview = None;
        let preview_part_id = message
            .text_body
            .first()
            .or_else(|| message.html_body.first())
            .copied()
            .unwrap_or(u32::MAX);

        for (part_id, part) in message.parts.iter().take(MAX_MESSAGE_PARTS).enumerate() {
            let part_id = part_id as u32;
            match &part.body {
                mail_parser::PartType::Text(text) => {
                    if part_id == preview_part_id {
                        preview =
                            preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
                    }

                    if !message.text_body.contains(&part_id)
                        && !message.html_body.contains(&part_id)
                    {
                        has_attachments = true;
                    }
                }
                mail_parser::PartType::Html(html) => {
                    let text = html_to_text(html);
                    if part_id == preview_part_id {
                        preview =
                            preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
                    }

                    if !message.text_body.contains(&part_id)
                        && !message.html_body.contains(&part_id)
                    {
                        has_attachments = true;
                    }
                }
                mail_parser::PartType::Binary(_) | mail_parser::PartType::Message(_)
                    if !has_attachments =>
                {
                    has_attachments = true;
                }
                _ => {}
            }
        }

        // Build metadata
        let root_part = message.root_part();
        let metadata = MessageMetadata {
            preview: preview.unwrap_or_default().into_owned(),
            size: message.raw_message.len() as u32,
            raw_headers: message
                .raw_message
                .as_ref()
                .get(root_part.offset_header as usize..root_part.offset_body as usize)
                .unwrap_or_default()
                .to_vec(),
            contents: vec![],
            received_at,
            has_attachments,
            blob_hash,
        }
        .with_contents(message);

        // Link blob
        self.set(
            BlobOp::Link {
                hash: metadata.blob_hash.clone(),
            },
            Vec::new(),
        );

        // Store message data
        self.custom(ObjectIndexBuilder::<(), _>::new().with_changes(data))
            .caused_by(trc::location!())?;

        // Store message metadata
        self.set(
            EmailField::Metadata,
            Archiver::new(metadata)
                .serialize()
                .caused_by(trc::location!())?,
        );

        Ok(self)
    }
}
