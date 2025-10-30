/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

use ahash::AHashMap;
use nlp::{
    language::{
        Language,
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
        stemmer::Stemmer,
    },
    tokenizers::word::WordTokenizer,
};
use trc::AddContext;
use types::collection::Collection;

use crate::{
    IterateParams, SerializeInfallible, Store, U32_LEN, ValueKey,
    backend::MAX_TOKEN_LENGTH,
    dispatch::DocumentSet,
    search::IndexDocument,
    write::{BatchBuilder, Operation, ValueClass, ValueOp, key::DeserializeBigEndian},
};

pub const TERM_INDEX_VERSION: u8 = 1;

impl Store {
    pub async fn index_insert(&self, document: IndexDocument) -> trc::Result<()> {
        /*let mut detect = LanguageDetector::new();
        let mut tokens: AHashMap<BitmapHash, Postings> = AHashMap::new();
        let mut parts = Vec::new();
        let mut position = 0;

        for text in document.parts {
            match text.typ {
                Type::Text(language) => {
                    let language = if language == Language::Unknown {
                        detect.detect(&text.text, MIN_LANGUAGE_SCORE)
                    } else {
                        language
                    };
                    parts.push((text.field, language, text.text));
                }
                Type::Tokenize => {
                    let field = u8::from(text.field);
                    for token in WordTokenizer::new(text.text.as_ref(), MAX_TOKEN_LENGTH) {
                        tokens
                            .entry(BitmapHash::new(token.word.as_ref()))
                            .or_default()
                            .insert(TokenType::word(field), position);
                        position += 1;
                    }
                    position += 10;
                }
                Type::Keyword => {
                    let value = text.text.as_ref();
                    if !value.is_empty() {
                        let field = u8::from(text.field);
                        tokens
                            .entry(BitmapHash::new(value))
                            .or_default()
                            .insert_keyword(TokenType::word(field));
                    }
                }
            }
        }

        let default_language = detect
            .most_frequent_language()
            .unwrap_or(document.default_language);

        for (field, language, text) in parts.into_iter() {
            let language = if language != Language::Unknown {
                language
            } else {
                default_language
            };
            let field: u8 = field.into();

            for token in Stemmer::new(&text, language, MAX_TOKEN_LENGTH) {
                tokens
                    .entry(BitmapHash::new(token.word.as_ref()))
                    .or_default()
                    .insert(TokenType::word(field), position);

                if let Some(stemmed_word) = token.stemmed_word {
                    tokens
                        .entry(BitmapHash::new(stemmed_word.as_ref()))
                        .or_default()
                        .insert_keyword(TokenType::stemmed(field));
                }

                position += 1;
            }

            position += 10;
        }

        if tokens.is_empty() {
            return Ok(());
        }

        // Serialize keys
        let mut keys = Vec::with_capacity(tokens.len());
        for (hash, postings) in tokens.into_iter() {
            keys.push(Operation::Value {
                class: ValueClass::FtsIndex(hash),
                op: ValueOp::Set {
                    value: postings.serialize(),
                    version_offset: None,
                },
            });
        }

        // Commit index
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(document.account_id)
            .with_collection(document.collection)
            .with_document(document.document_id);

        for key in keys.into_iter() {
            if batch.is_large_batch() {
                self.write(batch.build_all()).await?;
                batch = BatchBuilder::new();
                batch
                    .with_account_id(document.account_id)
                    .with_collection(document.collection)
                    .with_document(document.document_id);
            }
            batch.any_op(key);
        }

        if !batch.is_empty() {
            self.write(batch.build_all()).await?;
        }*/

        Ok(())
    }

    pub async fn index_remove(
        &self,
        account_id: u32,
        collection: Collection,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        // Find keys to delete
        /*let mut delete_keys: AHashMap<u32, Vec<ValueClass>> = AHashMap::new();
        self.iterate(
            IterateParams::new(
                ValueKey {
                    account_id,
                    collection: collection as u8,
                    document_id: 0,
                    class: ValueClass::FtsIndex(BitmapHash {
                        hash: [0; 8],
                        len: 1,
                    }),
                },
                ValueKey {
                    account_id: account_id + 1,
                    collection: collection as u8,
                    document_id: 0,
                    class: ValueClass::FtsIndex(BitmapHash {
                        hash: [0; 8],
                        len: 1,
                    }),
                },
            )
            .no_values(),
            |key, _| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                if document_ids.contains(document_id) {
                    let mut hash = [0u8; 8];
                    let (hash, len) = match key.len() - (U32_LEN * 2) - 1 {
                        9 => {
                            hash[..8].copy_from_slice(&key[U32_LEN..U32_LEN + 8]);
                            (hash, key[key.len() - U32_LEN - 2])
                        }
                        len @ (1..=7) => {
                            hash[..len].copy_from_slice(&key[U32_LEN..U32_LEN + len]);
                            (hash, len as u8)
                        }
                        0 => {
                            // Temporary fix for empty keywords
                            (hash, 0)
                        }
                        invalid => {
                            return Err(trc::Error::corrupted_key(key, None, trc::location!())
                                .ctx(trc::Key::Reason, "Invalid bitmap key length")
                                .ctx(trc::Key::Size, invalid));
                        }
                    };

                    delete_keys
                        .entry(document_id)
                        .or_default()
                        .push(ValueClass::FtsIndex(BitmapHash { hash, len }));
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        // Remove keys
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(collection);

        for (document_id, keys) in delete_keys {
            batch.with_document(document_id);

            for key in keys {
                if batch.is_large_batch() {
                    self.write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                    batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(collection)
                        .with_document(document_id);
                }
                batch.any_op(Operation::Value {
                    class: key,
                    op: ValueOp::Clear,
                });
            }
        }

        if !batch.is_empty() {
            self.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }*/

        Ok(())
    }

    pub async fn index_remove_all(&self, _: u32) -> trc::Result<()> {
        // No-op
        // Term indexes are stored in the same key range as the document

        Ok(())
    }
}
