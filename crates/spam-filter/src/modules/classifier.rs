/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Email, IpParts, SpamFilterContext, TextPart, analysis::url::UrlParts};
use common::config::spamfilter::SpamClassifierModel;
use common::{Server, config::spamfilter::Location, ipc::BroadcastEvent};
use mail_auth::DmarcResult;
use mail_parser::MimeHeaders;
use nlp::{
    classifier::{feature::Feature, sgd::TextClassifier},
    tokenizers::{
        stream::{WordStemTokenizer, symbols},
        types::TokenType,
    },
};
use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
    hash::{Hash, RandomState},
    sync::Arc,
};
use store::write::{BlobLink, now};
use store::{
    IterateParams, Serialize, U32_LEN, U64_LEN, ValueKey,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, BlobOp, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use types::{blob_hash::BlobHash, collection::Collection, field::PrincipalField};

pub trait SpamClassifier {
    fn spam_train(&self, retrain: bool) -> impl Future<Output = trc::Result<()>> + Send;

    fn spam_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

struct TrainingSample {
    hash: BlobHash,
    account_id: u32,
    is_spam: bool,
    remove: Option<u64>,
}

impl SpamClassifier for Server {
    async fn spam_train(&self, retrain: bool) -> trc::Result<()> {
        let todo = "parse ASN and other stuff, build context properly";
        let Some(config) = &self.core.spam.classifier else {
            return Ok(());
        };

        // Fetch model
        let mut model = if !retrain
            && let Some(model) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                    u32::MAX,
                    Collection::Principal,
                    u32::MAX,
                    PrincipalField::SpamModel,
                ))
                .await
                .and_then(|archive| match archive {
                    Some(archive) => archive.deserialize::<SpamClassifierModel>().map(Some),
                    None => Ok(None),
                })
                .caused_by(trc::location!())?
        {
            model
        } else {
            SpamClassifierModel {
                classifier: TextClassifier::new(config.feature_hash_size),
                ham_count: 0,
                spam_count: 0,
                last_sample_expiry: 0,
                last_trained_at: 0,
            }
        };

        // Fetch blob hashes for samples
        let mut samples = Vec::new();
        let mut remove_entries = false;
        let from_key = ValueKey {
            account_id: 0,
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::SpamSample {
                hash: BlobHash::default(),
                until: model.last_sample_expiry + 1,
            }),
        };
        let to_key = ValueKey {
            account_id: u32::MAX,
            collection: u8::MAX,
            document_id: u32::MAX,
            class: ValueClass::Blob(BlobOp::SpamSample {
                hash: BlobHash::new_max(),
                until: u64::MAX,
            }),
        };
        self.store()
            .iterate(
                IterateParams::new(from_key, to_key).ascending(),
                |key, value| {
                    let until = key.deserialize_be_u64(1)?;
                    let account_id = key.deserialize_be_u32(U64_LEN + 1)?;
                    let hash = BlobHash::try_from_hash_slice(
                        key.get(U64_LEN + U32_LEN + 1..).ok_or_else(|| {
                            trc::Error::corrupted_key(key, value.into(), trc::location!())
                        })?,
                    )
                    .unwrap();
                    let (Some(is_spam), Some(hold)) = (value.first(), value.get(1)) else {
                        return Err(trc::Error::corrupted_key(
                            key,
                            value.into(),
                            trc::location!(),
                        ));
                    };

                    let do_remove = *hold == 0;
                    samples.push(TrainingSample {
                        hash,
                        account_id,
                        is_spam: *is_spam == 1,
                        remove: do_remove.then_some(until),
                    });

                    remove_entries |= do_remove;
                    model.last_sample_expiry = until;

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if !samples.is_empty() {
            let todo = "log no new samples";
            return Ok(());
        }

        // Train model
        for chunk in samples.chunks(config.train_batch_size.max(10)) {
            let todo = "do magic here";

            let mut samples = Vec::with_capacity(chunk.len());
            for sample in chunk {
                if sample.is_spam {
                    model.spam_count += 1;
                } else {
                    model.ham_count += 1;
                }
                samples.push(sample);
            }

            let todo = "use blocking";
        }

        // Store updated model
        model.last_trained_at = now();
        let archiver = Archiver::new(model);
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(u32::MAX)
            .with_collection(Collection::Principal)
            .with_document(u32::MAX)
            .set(
                ValueClass::Property(PrincipalField::SpamModel.into()),
                archiver.serialize().caused_by(trc::location!())?,
            );
        self.store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        // Reload model
        let model = archiver.inner;
        if model.ham_count >= config.min_ham_samples && model.spam_count >= config.min_spam_samples
        {
            self.inner
                .data
                .spam_classifier
                .store(Arc::new(common::SpamClassifier {
                    model: model.classifier,
                    last_trained_at: model.last_trained_at,
                }));
            self.cluster_broadcast(BroadcastEvent::ReloadSpamFilter)
                .await;
        }

        // Remove samples marked for deletion
        if remove_entries {
            let mut batch = BatchBuilder::new();
            for sample in samples {
                if let Some(until) = sample.remove {
                    batch
                        .with_account_id(sample.account_id)
                        .clear(BlobOp::Link {
                            hash: sample.hash.clone(),
                            to: BlobLink::Temporary { until },
                        })
                        .clear(BlobOp::SpamSample {
                            hash: sample.hash,
                            until,
                        });
                    if batch.is_large_batch() {
                        self.store()
                            .write(batch.build_all())
                            .await
                            .caused_by(trc::location!())?;
                        batch = BatchBuilder::new();
                    }
                }
            }
            if !batch.is_empty() {
                self.store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        Ok(())
    }

    async fn spam_classify(&self, ctx: &mut SpamFilterContext<'_>) -> trc::Result<()> {
        let classifier = self.inner.data.spam_classifier.load_full();
        let model = &classifier.model;

        if model.is_active() {
            let mut classifier_confidence = Vec::with_capacity(ctx.input.env_rcpt_to.len());
            let mut has_prediction = false;
            let mut tokens = ctx.classifier_tokens().0;
            let feature_builder = model.feature_builder();
            feature_builder.scale(&mut tokens);

            for rcpt in &ctx.input.env_rcpt_to {
                let prediction = if let Some(account_id) = self
                    .directory()
                    .email_to_id(rcpt)
                    .await
                    .caused_by(trc::location!())?
                {
                    has_prediction = true;
                    model
                        .predict(&feature_builder.build(&tokens, account_id.into()))
                        .into()
                } else {
                    None
                };
                classifier_confidence.push(prediction);
            }

            if has_prediction {
                ctx.result.classifier_confidence = classifier_confidence;
            } else {
                // None of the recipients are local, default to global model prediction
                let prediction = model.predict(&feature_builder.build(&tokens, None));
                ctx.result.classifier_confidence =
                    vec![prediction.into(); ctx.input.env_rcpt_to.len()];
            }
        }

        Ok(())
    }
}

const MAX_TOKEN_LENGTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Token<'x> {
    // User types
    Word { value: Cow<'x, str> },
    Number { code: [u8; 3] },
    Alphanumeric { code: [u8; 4] },
    Symbol { value: String },

    // User and global types
    Sender { value: Cow<'x, str> },
    Asn { number: [u8; 4] },
    Url { value: Cow<'x, str> },
    Email { value: Cow<'x, str> },
    Hostname { value: &'x str },
    Attachment { value: Cow<'x, str> },
    MimeType { value: String },
}

#[derive(Debug)]
struct Tokens<'x>(HashMap<Token<'x>, f32, RandomState>);

impl<'x> SpamFilterContext<'x> {
    fn classifier_tokens(&'x self) -> Tokens<'x> {
        let mut tokens = Tokens::default();

        // Add From addresses
        if !matches!(self.input.dmarc_result, Some(DmarcResult::Pass)) {
            tokens.insert(Token::Sender { value: "!".into() });
        }
        for email in [&self.output.env_from_addr, &self.output.from.email] {
            tokens.insert_email(email, true);
        }

        // Add Email addresses
        for email in &self.output.emails {
            let is_sender = match &email.location {
                Location::HeaderReplyTo | Location::HeaderDnt => true,
                Location::BodyText
                | Location::BodyHtml
                | Location::Attachment
                | Location::HeaderSubject => false,
                _ => continue,
            };

            tokens.insert_email(&email.element.email, is_sender);
        }

        // Add URLs
        for url in &self.output.urls {
            if let Some(url) = &url.element.url_parsed {
                if let Some(host) = &url.host.sld {
                    tokens.insert(Token::Url { value: host.into() });
                    if host != &url.host.fqdn {
                        tokens.insert(Token::Url {
                            value: url.host.fqdn.as_str().into(),
                        });
                    }
                } else {
                    tokens.insert(Token::Url {
                        value: url.host.fqdn.as_str().into(),
                    });
                }
                if let Some(path) = url.parts.path_and_query() {
                    for token in path.as_str().split(|c: char| !c.is_alphanumeric()) {
                        if token.len() > 1 {
                            let token = truncate_word(token, MAX_TOKEN_LENGTH);
                            tokens.insert(Token::Url {
                                value: format!("_{token}").into(),
                            });
                        }
                    }
                }
            }
        }

        // Add hostnames
        for domain in &self.output.domains {
            if matches!(
                domain.location,
                Location::HeaderReceived | Location::HeaderMid | Location::Ehlo | Location::Tcp
            ) {
                tokens.insert(Token::Hostname {
                    value: &domain.element,
                });
            }
        }

        // Add ASN
        if let Some(asn) = self.input.asn {
            tokens.insert(Token::Asn {
                number: asn.to_be_bytes(),
            });
        }

        // Add MIME and attachment indicators
        for part in &self.input.message.parts {
            if let Some(name) = part.attachment_name()
                && let Some((name, ext)) = name.rsplit_once('.')
            {
                if !ext.is_empty() {
                    tokens.insert(Token::Attachment {
                        value: lower_prefix("!", truncate_word(ext, MAX_TOKEN_LENGTH)).into(),
                    });
                }
                for token in name.split(|c: char| !c.is_alphanumeric()) {
                    if token.len() > 1 {
                        tokens.insert(Token::Attachment {
                            value: lower_prefix("_", truncate_word(token, MAX_TOKEN_LENGTH)).into(),
                        });
                    }
                }
            }

            if let Some(ct) = part.content_type() {
                let mut ct_lower = String::with_capacity(
                    ct.c_type.len() + ct.c_subtype.as_ref().map_or(0, |s| s.len()),
                );
                for ch in ct.c_type.chars() {
                    ct_lower.push(ch.to_ascii_lowercase());
                }
                if let Some(st) = &ct.c_subtype {
                    ct_lower.push('/');
                    for ch in st.chars() {
                        ct_lower.push(ch.to_ascii_lowercase());
                    }
                }

                tokens.insert(Token::MimeType { value: ct_lower });
            }
        }

        // Tokenize the subject
        for token in &self.output.subject_tokens {
            tokens.insert_type(
                &WordStemTokenizer::new(&self.output.subject_thread_lc),
                token,
            );
        }

        // Tokenize the text parts
        let body_idx = self
            .input
            .message
            .html_body
            .first()
            .or_else(|| self.input.message.text_body.first())
            .map(|idx| *idx as usize);
        let mut alt_tokens = Tokens::default();
        for (idx, part) in self.output.text_parts.iter().enumerate() {
            if Some(idx) == body_idx
                || (!self.input.message.text_body.contains(&(idx as u32))
                    && !self.input.message.html_body.contains(&(idx as u32)))
            {
                tokens.insert_text_part(part);
            } else {
                alt_tokens.insert_text_part(part);
            }
        }
        if !alt_tokens.0.is_empty() {
            for (token, count) in alt_tokens.0.into_iter() {
                if let Entry::Vacant(entry) = tokens.0.entry(token) {
                    entry.insert(count);
                }
            }
        }

        tokens
    }
}

impl<'x> Tokens<'x> {
    fn insert_text_part(&mut self, part: &'x TextPart<'x>) {
        match part {
            TextPart::Plain { text_body, tokens } => {
                let word_tokenizer = WordStemTokenizer::new(text_body);

                for token in tokens {
                    self.insert_type(&word_tokenizer, token);
                }
            }
            TextPart::Html {
                text_body, tokens, ..
            } => {
                let word_tokenizer = WordStemTokenizer::new(text_body);
                for token in tokens {
                    self.insert_type(&word_tokenizer, token);
                }
            }
            TextPart::None => (),
        }
    }

    fn insert_type(
        &mut self,
        word_tokenizer: &WordStemTokenizer,
        token: &'x TokenType<Cow<'x, str>, Email, UrlParts<'x>, IpParts>,
    ) {
        match token {
            TokenType::Alphabetic(word) => {
                if word.chars().all(|c| c.is_lowercase() || !c.is_uppercase()) {
                    word_tokenizer.tokenize(word, |value| match value {
                        Cow::Borrowed(value) => {
                            self.insert(Token::Word {
                                value: truncate_word(value, MAX_TOKEN_LENGTH).into(),
                            });
                        }
                        Cow::Owned(value) => {
                            if value.len() <= MAX_TOKEN_LENGTH {
                                self.insert(Token::Word {
                                    value: value.into(),
                                });
                            } else {
                                self.insert(Token::Word {
                                    value: truncate_word(&value, MAX_TOKEN_LENGTH)
                                        .to_string()
                                        .into(),
                                });
                            }
                        }
                    });
                } else {
                    let word = word.to_lowercase();
                    word_tokenizer.tokenize(&word, |token| {
                        self.insert(Token::Word {
                            value: truncate_word(token.as_ref(), MAX_TOKEN_LENGTH)
                                .to_string()
                                .into(),
                        });
                    });
                }
            }
            TokenType::Alphanumeric(word) => {
                self.insert(Token::from_alphanumeric(word.as_ref()));
            }
            TokenType::UrlNoHost(url) => {
                for token in url.to_lowercase().split(|c: char| !c.is_alphanumeric()) {
                    if token.len() > 1 {
                        let token = truncate_word(token, MAX_TOKEN_LENGTH);
                        self.insert(Token::Url {
                            value: format!("_{token}").into(),
                        });
                    }
                }
            }
            TokenType::Other(ch) => {
                let value = ch.to_string();
                if symbols(&value) {
                    self.insert(Token::Symbol { value });
                }
            }
            TokenType::Integer(word) => {
                self.insert(Token::from_number(false, word.as_ref()));
            }
            TokenType::Float(word) => {
                self.insert(Token::from_number(true, word.as_ref()));
            }
            TokenType::Email(_)
            | TokenType::Url(_)
            | TokenType::UrlNoScheme(_)
            | TokenType::IpAddr(_)
            | TokenType::Punctuation(_)
            | TokenType::Space => {}
        }
    }

    fn insert(&mut self, token: Token<'x>) {
        *self.0.entry(token).or_insert(0.0) += 1.0;
    }

    fn insert_if_missing(&mut self, token: Token<'x>) {
        self.0.entry(token).or_insert(1.0);
    }

    fn insert_email(&mut self, email: &'x Email, is_sender: bool) {
        if is_sender {
            self.insert_if_missing(Token::Sender {
                value: email.address.as_str().into(),
            });
            self.insert_if_missing(Token::Sender {
                value: email.domain_part.fqdn.as_str().into(),
            });
            if let Some(sld) = &email.domain_part.sld
                && sld != &email.domain_part.fqdn
            {
                self.insert_if_missing(Token::Sender { value: sld.into() });
            }
        } else {
            self.insert_if_missing(Token::Email {
                value: email.address.as_str().into(),
            });
            self.insert_if_missing(Token::Email {
                value: email.domain_part.fqdn.as_str().into(),
            });
            if let Some(sld) = &email.domain_part.sld
                && sld != &email.domain_part.fqdn
            {
                self.insert_if_missing(Token::Email { value: sld.into() });
            }
        }
    }
}

impl Token<'static> {
    fn from_alphanumeric(s: &str) -> Self {
        // Character class counts
        let mut upper = 0u32;
        let mut lower = 0u32;
        let mut digit = 0u32;
        let mut len = 0;
        let mut char_types = Vec::with_capacity(len);
        for c in s.chars() {
            let char_type = CharType::from_char(c);
            char_types.push(char_type);
            match char_type {
                CharType::Upper => upper += 1,
                CharType::Lower => lower += 1,
                CharType::Digit => digit += 1,
                CharType::Other => (),
            }
            len += 1;
        }

        // Determine dominant composition
        let composition = match (upper > 0, lower > 0, digit > 0) {
            (true, false, false) => b'U',  // UPPERCASE only
            (false, true, false) => b'L',  // lowercase only
            (false, false, true) => b'D',  // digits only
            (true, true, false) => b'A',   // Alphabetic mixed case
            (true, false, true) => b'H',   // Upper + digits (common in codes)
            (false, true, true) => b'M',   // lower + digits (common in identifiers)
            (true, true, true) => b'X',    // eXtreme mix - all three
            (false, false, false) => b'E', // empty/invalid
        };

        // Length bucket (log-ish scale)
        let len_code = match len {
            1 => b'1',
            2 => b'2',
            3 => b'3',
            4 => b'4',
            5..=6 => b'5',
            7..=8 => b'6',
            9..=12 => b'7',
            13..=16 => b'8',
            17..=32 => b'9',
            _ => b'Z',
        };

        // Ratio encoding (which class dominates)
        let max_count = upper.max(lower).max(digit);
        let dominance = (max_count * 100) / len.min(1) as u32;
        let ratio = match dominance {
            0..=50 => b'B',  // Balanced
            51..=75 => b'P', // Partial dominance
            76..=99 => b'D', // Dominant
            _ => b'O',       // One class only (100%)
        };

        // Run code
        let mut run_count = 0;
        if len > 1 {
            let mut prev_type = char_types[0];
            for &current_type in char_types.iter().skip(1) {
                if current_type != prev_type {
                    run_count += 1;
                    prev_type = current_type;
                }
            }
        }
        let run_ratio = (run_count as f64) / ((len - 1) as f64);
        let run_code = match run_ratio {
            r if r <= 0.1 => b'0', // Very long runs (e.g., AAAABBBB)
            r if r <= 0.3 => b'1', // Moderate runs
            r if r <= 0.5 => b'2', // Balanced runs/alternation
            r if r <= 0.7 => b'3', // High alternation
            _ => b'4',             // Near maximum alternation (e.g., A1A1A1)
        };

        Token::Alphanumeric {
            code: [composition, len_code, ratio, run_code],
        }
    }

    fn from_number(is_float: bool, num: &str) -> Self {
        Token::Number {
            code: [
                u8::from(is_float),
                u8::from(num.starts_with('-')),
                num.as_bytes()
                    .iter()
                    .filter(|c| c.is_ascii_digit())
                    .count()
                    .min(u8::MAX as usize) as u8,
            ],
        }
    }
}

fn lower_prefix(prefix: &str, value: &str) -> String {
    let mut result = String::with_capacity(prefix.len() + value.len());
    result.push_str(prefix);
    for ch in value.chars() {
        for lower_ch in ch.to_lowercase() {
            result.push(lower_ch);
        }
    }
    result
}

fn truncate_word(word: &str, max_len: usize) -> &str {
    if word.len() <= max_len {
        word
    } else {
        let mut pos = 0;
        for (count, (idx, _)) in word.char_indices().enumerate() {
            pos = idx;
            if count == max_len {
                break;
            }
        }
        &word[..pos]
    }
}

impl Feature for Token<'_> {
    fn prefix(&self) -> u16 {
        match self {
            Token::Word { .. } => 0,
            Token::Number { .. } => 1,
            Token::Alphanumeric { .. } => 2,
            Token::Symbol { .. } => 3,
            Token::Sender { .. } => 4,
            Token::Asn { .. } => 5,
            Token::Url { .. } => 6,
            Token::Email { .. } => 7,
            Token::Hostname { .. } => 8,
            Token::Attachment { .. } => 9,
            Token::MimeType { .. } => 10,
        }
    }

    fn value(&self) -> &[u8] {
        match self {
            Token::Word { value } => value.as_bytes(),
            Token::Number { code } => code,
            Token::Alphanumeric { code } => code,
            Token::Symbol { value } => value.as_bytes(),
            Token::Sender { value } => value.as_bytes(),
            Token::Asn { number } => number,
            Token::Url { value } => value.as_bytes(),
            Token::Email { value } => value.as_bytes(),
            Token::Hostname { value } => value.as_bytes(),
            Token::Attachment { value } => value.as_bytes(),
            Token::MimeType { value } => value.as_bytes(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CharType {
    Upper,
    Lower,
    Digit,
    Other,
}

impl CharType {
    fn from_char(c: char) -> CharType {
        match c {
            'A'..='Z' => CharType::Upper,
            'a'..='z' => CharType::Lower,
            '0'..='9' => CharType::Digit,
            _ => CharType::Other,
        }
    }
}

impl<'x> Default for Tokens<'x> {
    fn default() -> Self {
        Tokens(HashMap::with_capacity(128))
    }
}
