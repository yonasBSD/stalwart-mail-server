/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    crypto::{EncryptMessage, EncryptMessageError},
    index::{MAX_SORT_FIELD_LENGTH, TrimTextValue},
};
use crate::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::{INBOX_ID, JUNK_ID, UidMailbox},
    message::{
        crypto::EncryptionParams,
        index::{IndexMessage, VisitText},
        metadata::MessageData,
    },
};
use common::{Server, auth::AccessToken};
use directory::Permission;
use groupware::{
    calendar::itip::{ItipIngest, ItipIngestError},
    scheduling::{ItipError, ItipMessages},
};
use mail_parser::{
    Header, HeaderName, HeaderValue, Message, MessageParser, MimeHeaders, PartType,
    parsers::fields::thread::thread_name,
};
use spam_filter::{
    SpamFilterInput, analysis::init::SpamFilterInit, modules::bayes::BayesClassifier,
};
use std::future::Future;
use std::{borrow::Cow, fmt::Write, time::Instant};
use store::{
    IndexKeyPrefix, IterateParams, U32_LEN, ValueKey,
    ahash::AHashMap,
    write::{
        BatchBuilder, IndexPropertyClass, TaskQueueClass, ValueClass, key::DeserializeBigEndian,
        now,
    },
};
use trc::{AddContext, MessageIngestEvent};
use types::{
    blob::{BlobClass, BlobId},
    collection::{Collection, SyncCollection},
    field::{ContactField, EmailField, MailboxField, PrincipalField},
    keyword::Keyword,
};
use utils::{
    cheeky_hash::{CheekyHash, CheekyHashMap},
    sanitize_email,
};

#[derive(Default)]
pub struct IngestedEmail {
    pub document_id: u32,
    pub thread_id: u32,
    pub change_id: u64,
    pub blob_id: BlobId,
    pub size: usize,
    pub imap_uids: Vec<u32>,
}

pub struct IngestEmail<'x> {
    pub raw_message: &'x [u8],
    pub message: Option<Message<'x>>,
    pub access_token: &'x AccessToken,
    pub mailbox_ids: Vec<u32>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<u64>,
    pub source: IngestSource<'x>,
    pub spam_classify: bool,
    pub spam_train: bool,
    pub session_id: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngestSource<'x> {
    Smtp {
        deliver_to: &'x str,
        is_sender_authenticated: bool,
    },
    Jmap,
    Imap,
    Restore,
}

pub trait EmailIngest: Sync + Send {
    fn email_ingest(
        &self,
        params: IngestEmail,
    ) -> impl Future<Output = trc::Result<IngestedEmail>> + Send;
    fn find_thread_id(
        &self,
        account_id: u32,
        thread_name: &str,
        message_ids: &CheekyHashMap<bool>,
    ) -> impl Future<Output = trc::Result<ThreadResult>> + Send;
    fn assign_imap_uid(
        &self,
        account_id: u32,
        mailbox_id: u32,
    ) -> impl Future<Output = trc::Result<u32>> + Send;
    fn email_bayes_can_train(&self, access_token: &AccessToken) -> bool;
}

pub struct ThreadResult {
    pub thread_id: Option<u32>,
    pub thread_hash: CheekyHash,
    pub merge_ids: Vec<u32>,
    pub duplicate_ids: Vec<u32>,
}

impl EmailIngest for Server {
    #[allow(clippy::blocks_in_conditions)]
    async fn email_ingest(&self, mut params: IngestEmail<'_>) -> trc::Result<IngestedEmail> {
        // Check quota
        let start_time = Instant::now();
        let account_id = params.access_token.primary_id;
        let tenant_id = params.access_token.tenant.map(|t| t.id);
        let mut raw_message_len = params.raw_message.len() as u64;
        let resource_token = params.access_token.as_resource_token();
        self.has_available_quota(&resource_token, raw_message_len)
            .await
            .caused_by(trc::location!())?;

        // Parse message
        let mut raw_message = Cow::from(params.raw_message);
        let mut message = params.message.ok_or_else(|| {
            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                .ctx(trc::Key::Code, 550)
                .ctx(trc::Key::Reason, "Failed to parse e-mail message.")
        })?;

        let mut is_spam = false;
        let mut train_spam = None;
        let mut extra_headers = String::new();
        let mut extra_headers_parsed = Vec::new();
        let mut itip_messages = Vec::new();
        match params.source {
            IngestSource::Smtp {
                deliver_to,
                is_sender_authenticated,
            } => {
                // Add delivered to header
                if self.core.smtp.session.data.add_delivered_to {
                    extra_headers = format!("Delivered-To: {deliver_to}\r\n");
                    extra_headers_parsed.push(Header {
                        name: HeaderName::Other("Delivered-To".into()),
                        value: HeaderValue::Text(deliver_to.into()),
                        offset_field: 0,
                        offset_start: 13,
                        offset_end: extra_headers.len() as u32,
                    });
                }

                // Spam classification and training
                if params.spam_classify
                    && self.core.spam.enabled
                    && params.mailbox_ids == [INBOX_ID]
                {
                    // Set the spam filter result
                    #[cfg(not(feature = "test_mode"))]
                    {
                        is_spam = self
                            .core
                            .spam
                            .headers
                            .status
                            .as_ref()
                            .and_then(|name| {
                                message
                                    .root_part()
                                    .headers
                                    .iter()
                                    .find(|h| h.name.as_str().eq_ignore_ascii_case(name.as_str()))
                                    .and_then(|v| v.value.as_text())
                            })
                            .is_some_and(|v| v.contains("Yes"));
                    }

                    #[cfg(feature = "test_mode")]
                    {
                        is_spam = self
                            .core
                            .spam
                            .headers
                            .status
                            .as_ref()
                            .and_then(|name| {
                                message
                                    .root_part()
                                    .headers
                                    .iter()
                                    .rev()
                                    .find(|h| h.name.as_str().eq_ignore_ascii_case(name.as_str()))
                                    .and_then(|v| v.value.as_text())
                            })
                            .is_some_and(|v| v.contains("Yes"));
                    }

                    // If the message is classified as spam, check whether the sender address is present in the user's address book
                    if is_spam
                        && self.core.spam.card_is_ham
                        && let Some(sender) = message
                            .from()
                            .and_then(|s| s.first())
                            .and_then(|s| s.address())
                            .and_then(sanitize_email)
                        && sender != deliver_to
                        && is_sender_authenticated
                        && !self
                            .document_exists(
                                account_id,
                                Collection::ContactCard,
                                ContactField::Email,
                                sender.as_bytes(),
                            )
                            .await
                            .caused_by(trc::location!())?
                    {
                        is_spam = false;
                        if self
                            .core
                            .spam
                            .bayes
                            .as_ref()
                            .is_some_and(|config| config.auto_learn_card_is_ham)
                        {
                            train_spam = Some(false);
                        }
                    }

                    // Classify the message with user's model
                    if let Some(bayes_config) = self.core.spam.bayes.as_ref().filter(|config| {
                        config.account_classify && params.spam_train && train_spam.is_none()
                    }) {
                        // Initialize spam filter
                        let ctx = self.spam_filter_init(SpamFilterInput::from_account_message(
                            &message,
                            account_id,
                            params.session_id,
                        ));

                        // Bayes classify
                        match self.bayes_classify(&ctx).await {
                            Ok(Some(score)) => {
                                let result = if score > bayes_config.score_spam {
                                    is_spam = true;
                                    "Yes"
                                } else if score < bayes_config.score_ham {
                                    is_spam = false;
                                    "No"
                                } else {
                                    "Unknown"
                                };

                                if let Some(header) = &self.core.spam.headers.bayes_result {
                                    let offset_field = extra_headers.len();
                                    let offset_start = offset_field + header.len() + 1;

                                    let _ = write!(
                                        &mut extra_headers,
                                        "{header}: {result}, {score:.2}\r\n",
                                    );

                                    extra_headers_parsed.push(Header {
                                        name: HeaderName::Other(header.into()),
                                        value: HeaderValue::Text(
                                            extra_headers
                                                [offset_start + 1..extra_headers.len() - 2]
                                                .into(),
                                        ),
                                        offset_field: offset_field as u32,
                                        offset_start: offset_start as u32,
                                        offset_end: extra_headers.len() as u32,
                                    });
                                }
                            }
                            Ok(None) => (),
                            Err(err) => {
                                trc::error!(err.caused_by(trc::location!()));
                            }
                        }
                    }

                    if is_spam {
                        params.mailbox_ids[0] = JUNK_ID;
                        params.keywords.push(Keyword::Junk);
                    }
                }

                // iMIP processing
                if self.core.groupware.itip_enabled
                    && params
                        .access_token
                        .has_permission(Permission::CalendarSchedulingReceive)
                    && is_sender_authenticated
                    && !is_spam
                {
                    let mut sender = None;
                    for part in &message.parts {
                        if part.content_type().is_some_and(|ct| {
                            ct.ctype().eq_ignore_ascii_case("text")
                                && ct
                                    .subtype()
                                    .is_some_and(|st| st.eq_ignore_ascii_case("calendar"))
                                && ct.has_attribute("method")
                        }) && let Some(itip_message) = part.text_contents()
                        {
                            if itip_message.len() < self.core.groupware.itip_inbound_max_ical_size {
                                if let Some(sender) = sender.get_or_insert_with(|| {
                                    message
                                        .from()
                                        .and_then(|s| s.first())
                                        .and_then(|s| s.address())
                                        .and_then(sanitize_email)
                                }) {
                                    match self
                                        .itip_ingest(
                                            params.access_token,
                                            &resource_token,
                                            sender,
                                            deliver_to,
                                            itip_message,
                                        )
                                        .await
                                    {
                                        Ok(message) => {
                                            if let Some(message) = message {
                                                itip_messages.push(message);
                                            }
                                            trc::event!(
                                                Calendar(trc::CalendarEvent::ItipMessageReceived),
                                                SpanId = params.session_id,
                                                From = sender.to_string(),
                                                AccountId = account_id,
                                            );
                                        }
                                        Err(ItipIngestError::Message(itip_error)) => {
                                            match itip_error {
                                                ItipError::NothingToSend
                                                | ItipError::OtherSchedulingAgent => (),
                                                err => {
                                                    trc::event!(
                                                        Calendar(
                                                            trc::CalendarEvent::ItipMessageError
                                                        ),
                                                        SpanId = params.session_id,
                                                        From = sender.to_string(),
                                                        AccountId = account_id,
                                                        Details = err.to_string(),
                                                    )
                                                }
                                            }
                                        }
                                        Err(ItipIngestError::Internal(err)) => {
                                            trc::error!(err.caused_by(trc::location!()));
                                        }
                                    }
                                }
                            } else {
                                trc::event!(
                                    Calendar(trc::CalendarEvent::ItipMessageError),
                                    SpanId = params.session_id,
                                    From = message
                                        .from()
                                        .and_then(|a| a.first())
                                        .and_then(|a| a.address())
                                        .map(|a| a.to_string()),
                                    AccountId = account_id,
                                    Details = "iMIP message too large",
                                    Limit = self.core.groupware.itip_inbound_max_ical_size,
                                    Size = itip_message.len(),
                                )
                            }
                        }
                    }
                }
            }
            IngestSource::Jmap | IngestSource::Imap
                if params.spam_train && self.core.spam.enabled =>
            {
                if params.keywords.contains(&Keyword::Junk) {
                    train_spam = Some(true);
                } else if params.keywords.contains(&Keyword::NotJunk) {
                    train_spam = Some(false);
                } else if params.mailbox_ids[0] == JUNK_ID {
                    train_spam = Some(true);
                } else if params.mailbox_ids[0] == INBOX_ID {
                    train_spam = Some(false);
                }
            }

            _ => (),
        }

        // Obtain message references and thread name
        let mut message_id = None;
        let mut message_ids = CheekyHashMap::default();
        let thread_result = {
            let mut subject = "";
            for header in message.root_part().headers().iter().rev() {
                match &header.name {
                    HeaderName::MessageId => header.value.visit_text(|id| {
                        if !id.is_empty() {
                            if message_id.is_none() {
                                message_id = id.to_string().into();
                            }
                            message_ids.insert(CheekyHash::new(id.as_bytes()), true);
                        }
                    }),
                    HeaderName::InReplyTo
                    | HeaderName::References
                    | HeaderName::ResentMessageId => {
                        header.value.visit_text(|id| {
                            if !id.is_empty() {
                                message_ids.insert(CheekyHash::new(id.as_bytes()), false);
                            }
                        });
                    }
                    HeaderName::Subject if subject.is_empty() => {
                        subject = thread_name(match &header.value {
                            HeaderValue::Text(text) => text.as_ref(),
                            HeaderValue::TextList(list) if !list.is_empty() => {
                                list.first().unwrap().as_ref()
                            }
                            _ => "",
                        })
                        .trim_text(MAX_SORT_FIELD_LENGTH);
                    }
                    _ => (),
                }
            }

            self.find_thread_id(account_id, subject, &message_ids)
                .await?
        };

        // Skip duplicate messages for SMTP ingestion
        if !thread_result.duplicate_ids.is_empty() && params.source.is_smtp() {
            // Fetch cached messages
            let cache = self
                .get_cached_messages(account_id)
                .await
                .caused_by(trc::location!())?;

            // Skip duplicate messages
            if !cache
                .in_mailbox(params.mailbox_ids.first().copied().unwrap_or(INBOX_ID))
                .any(|m| thread_result.duplicate_ids.contains(&m.document_id))
            {
                trc::event!(
                    MessageIngest(MessageIngestEvent::Duplicate),
                    SpanId = params.session_id,
                    AccountId = account_id,
                    MessageId = message_id,
                );

                return Ok(IngestedEmail {
                    document_id: 0,
                    thread_id: 0,
                    change_id: u64::MAX,
                    blob_id: BlobId::default(),
                    imap_uids: Vec::new(),
                    size: 0,
                });
            }
        }

        // Add additional headers to message
        if !extra_headers.is_empty() {
            let offset_start = extra_headers.len();
            raw_message_len += offset_start as u64;
            let mut new_message = Vec::with_capacity(raw_message_len as usize);
            new_message.extend_from_slice(extra_headers.as_bytes());
            new_message.extend_from_slice(raw_message.as_ref());
            raw_message = Cow::from(new_message);
            message.raw_message = raw_message.as_ref().into();

            // Adjust offsets
            let mut part_iter_stack = Vec::new();
            let mut part_iter = message.parts.iter_mut();

            loop {
                if let Some(part) = part_iter.next() {
                    // Increment header offsets
                    for header in part.headers.iter_mut() {
                        header.offset_field += offset_start as u32;
                        header.offset_start += offset_start as u32;
                        header.offset_end += offset_start as u32;
                    }

                    // Adjust part offsets
                    part.offset_body += offset_start as u32;
                    part.offset_end += offset_start as u32;
                    part.offset_header += offset_start as u32;

                    if let PartType::Message(sub_message) = &mut part.body
                        && sub_message.root_part().offset_header != 0
                    {
                        sub_message.raw_message = raw_message.as_ref().into();
                        part_iter_stack.push(part_iter);
                        part_iter = sub_message.parts.iter_mut();
                    }
                } else if let Some(iter) = part_iter_stack.pop() {
                    part_iter = iter;
                } else {
                    break;
                }
            }

            // Add extra headers to root part
            let root_part = &mut message.parts[0];
            root_part.offset_header = 0;
            extra_headers_parsed.append(&mut root_part.headers);
            root_part.headers = extra_headers_parsed;
        }

        // Encrypt message
        let do_encrypt = match params.source {
            IngestSource::Jmap | IngestSource::Imap => {
                self.core.jmap.encrypt && self.core.jmap.encrypt_append
            }
            IngestSource::Smtp { .. } => self.core.jmap.encrypt,
            IngestSource::Restore => false,
        };
        if do_encrypt
            && !message.is_encrypted()
            && let Some(encrypt_params_) = self
                .archive_by_property(
                    account_id,
                    Collection::Principal,
                    0,
                    PrincipalField::EncryptionKeys.into(),
                )
                .await
                .caused_by(trc::location!())?
        {
            let encrypt_params = encrypt_params_
                .unarchive::<EncryptionParams>()
                .caused_by(trc::location!())?;
            match message.encrypt(encrypt_params).await {
                Ok(new_raw_message) => {
                    raw_message = Cow::from(new_raw_message);
                    raw_message_len = raw_message.len() as u64;
                    message = MessageParser::default()
                        .parse(raw_message.as_ref())
                        .ok_or_else(|| {
                            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                                .ctx(trc::Key::Code, 550)
                                .ctx(
                                    trc::Key::Reason,
                                    "Failed to parse encrypted e-mail message.",
                                )
                        })?;

                    // Remove contents from parsed message
                    for part in &mut message.parts {
                        match &mut part.body {
                            PartType::Text(txt) | PartType::Html(txt) => {
                                *txt = Cow::from("");
                            }
                            PartType::Binary(bin) | PartType::InlineBinary(bin) => {
                                *bin = Cow::from(&[][..]);
                            }
                            PartType::Message(_) => {
                                part.body = PartType::Binary(Cow::from(&[][..]));
                            }
                            PartType::Multipart(_) => (),
                        }
                    }
                }
                Err(EncryptMessageError::Error(err)) => {
                    trc::bail!(
                        trc::StoreEvent::CryptoError
                            .into_err()
                            .caused_by(trc::location!())
                            .reason(err)
                    );
                }
                _ => unreachable!(),
            }
        }

        // Store blob
        let blob_id = self
            .put_blob(account_id, raw_message.as_ref(), false)
            .await
            .caused_by(trc::location!())?;

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(params.mailbox_ids.len());
        let mut imap_uids = Vec::with_capacity(params.mailbox_ids.len());
        for mailbox_id in &params.mailbox_ids {
            let uid = self
                .assign_imap_uid(account_id, *mailbox_id)
                .await
                .caused_by(trc::location!())?;
            mailbox_ids.push(UidMailbox::new(*mailbox_id, uid));
            imap_uids.push(uid);
        }

        // Build write batch
        let mut batch = BatchBuilder::new();
        let mailbox_ids_event = mailbox_ids
            .iter()
            .map(|m| trc::Value::from(m.mailbox_id))
            .collect::<Vec<_>>();
        batch.with_account_id(account_id);

        // Obtain document ID
        let document_id = self
            .store()
            .assign_document_ids(account_id, Collection::Email, 1)
            .await
            .caused_by(trc::location!())?;

        // Determine thread id
        let thread_id = if let Some(thread_id) = thread_result.thread_id {
            thread_id
        } else {
            batch
                .with_collection(Collection::Thread)
                .with_document(document_id)
                .log_container_insert(SyncCollection::Thread);
            document_id
        };

        let due = now();

        batch
            .with_collection(Collection::Email)
            .with_document(document_id)
            .index_message(
                account_id,
                tenant_id,
                message,
                blob_id.hash.clone(),
                MessageData {
                    mailboxes: mailbox_ids,
                    keywords: params.keywords,
                    thread_id,
                },
                params.received_at.unwrap_or_else(now),
            )
            .caused_by(trc::location!())?
            .set(
                ValueClass::IndexProperty(IndexPropertyClass::Hash {
                    property: EmailField::Threading.into(),
                    hash: thread_result.thread_hash,
                }),
                ThreadInfo::serialize(thread_id, &message_ids),
            )
            .set(
                ValueClass::TaskQueue(TaskQueueClass::IndexEmail { due }),
                MergeThreadTask::new(thread_result).serialize(),
            );

        // Request spam training
        if let Some(learn_spam) = train_spam {
            batch.set(
                ValueClass::TaskQueue(TaskQueueClass::BayesTrain { due, learn_spam }),
                vec![],
            );
        }

        // Add iTIP responses to batch
        if !itip_messages.is_empty() {
            ItipMessages::new(itip_messages)
                .queue(&mut batch)
                .caused_by(trc::location!())?;
        }

        // Insert and obtain ids
        let change_id = self
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?
            .last_change_id(account_id)?;

        // Request FTS index
        self.notify_task_queue();

        trc::event!(
            MessageIngest(match params.source {
                IngestSource::Smtp { .. } =>
                    if !is_spam {
                        MessageIngestEvent::Ham
                    } else {
                        MessageIngestEvent::Spam
                    },
                IngestSource::Jmap | IngestSource::Restore => MessageIngestEvent::JmapAppend,
                IngestSource::Imap => MessageIngestEvent::ImapAppend,
            }),
            SpanId = params.session_id,
            AccountId = account_id,
            DocumentId = document_id,
            MailboxId = mailbox_ids_event,
            BlobId = blob_id.hash.to_hex(),
            ChangeId = change_id,
            MessageId = message_id,
            Size = raw_message_len,
            Elapsed = start_time.elapsed(),
        );

        Ok(IngestedEmail {
            document_id,
            thread_id,
            change_id,
            blob_id: BlobId {
                hash: blob_id.hash,
                class: BlobClass::Linked {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                },
                section: blob_id.section,
            },
            size: raw_message_len as usize,
            imap_uids,
        })
    }

    async fn find_thread_id(
        &self,
        account_id: u32,
        thread_name: &str,
        message_ids: &CheekyHashMap<bool>,
    ) -> trc::Result<ThreadResult> {
        let mut result = ThreadResult {
            thread_id: None,
            thread_hash: CheekyHash::new(if !thread_name.is_empty() {
                thread_name
            } else {
                "!"
            }),
            merge_ids: vec![],
            duplicate_ids: vec![],
        };

        if message_ids.is_empty() {
            return Ok(result);
        }

        // Find thread ids
        let key_len = IndexKeyPrefix::len() + result.thread_hash.len() + U32_LEN;
        let document_id_pos = key_len - U32_LEN;
        let mut thread_ids = AHashMap::<u32, Vec<u32>>::with_capacity(16);
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
                            property: EmailField::Threading.into(),
                            hash: result.thread_hash,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
                            property: EmailField::Threading.into(),
                            hash: result.thread_hash,
                        }),
                    },
                )
                .ascending(),
                |key, value| {
                    if key.len() == key_len {
                        // Find matching references
                        let mut from_offset = U32_LEN;

                        while let Some(ref_hash) =
                            value.get(from_offset..).and_then(CheekyHash::deserialize)
                        {
                            if let Some(is_message_id) = message_ids.get(&ref_hash) {
                                let document_id = key.deserialize_be_u32(document_id_pos)?;
                                let thread_id = value.deserialize_be_u32(0)?;

                                if *is_message_id && from_offset == U32_LEN {
                                    result.duplicate_ids.push(document_id);
                                }

                                thread_ids.entry(thread_id).or_default().push(document_id);

                                return Ok(true);
                            }

                            from_offset += ref_hash.len();
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        match thread_ids.len() {
            0 => Ok(result),
            1 => {
                // Happy path, only one thread id
                result.thread_id = thread_ids.into_keys().next();
                Ok(result)
            }
            _ => {
                // Multiple thread ids that this message belongs to, merge them
                let mut max_thread_id = u32::MAX;
                let mut max_count = 0;
                for (thread_id, ids) in thread_ids {
                    if ids.len() > max_count {
                        max_count = ids.len();
                        max_thread_id = thread_id;
                    }
                    result.merge_ids.extend(ids);
                }
                result.thread_id = Some(max_thread_id);
                Ok(result)
            }
        }
    }

    async fn assign_imap_uid(&self, account_id: u32, mailbox_id: u32) -> trc::Result<u32> {
        // Increment UID next
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox)
            .with_document(mailbox_id)
            .add_and_get(MailboxField::UidCounter, 1);
        self.core
            .storage
            .data
            .write(batch.build_all())
            .await
            .and_then(|v| v.last_counter_id().map(|id| id as u32))
    }

    fn email_bayes_can_train(&self, access_token: &AccessToken) -> bool {
        self.core.spam.bayes.as_ref().is_some_and(|bayes| {
            bayes.account_classify && access_token.has_permission(Permission::SpamFilterTrain)
        })
    }
}

impl IngestSource<'_> {
    pub fn is_smtp(&self) -> bool {
        matches!(self, Self::Smtp { .. })
    }
}

pub struct MergeThreadTask {
    pub thread_hash: CheekyHash,
    pub duplicate_ids: Vec<u32>,
}

impl MergeThreadTask {
    pub(crate) fn new(thread_result: ThreadResult) -> Self {
        Self {
            thread_hash: thread_result.thread_hash,
            duplicate_ids: thread_result.duplicate_ids,
        }
    }

    pub(crate) fn serialize(&self) -> Vec<u8> {
        if !self.duplicate_ids.is_empty() {
            let mut buf =
                Vec::with_capacity(self.thread_hash.len() + self.duplicate_ids.len() * U32_LEN);
            buf.extend_from_slice(self.thread_hash.as_bytes());
            for id in &self.duplicate_ids {
                buf.extend_from_slice(&id.to_be_bytes());
            }
            buf
        } else {
            vec![]
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if !bytes.is_empty() {
            let thread_hash = CheekyHash::deserialize(bytes)?;
            let mut duplicate_ids = Vec::new();
            let mut start_offset = thread_hash.len();

            while let Some(id_bytes) = bytes.get(start_offset..start_offset + U32_LEN) {
                duplicate_ids.push(u32::from_be_bytes(id_bytes.try_into().ok()?));
                start_offset += U32_LEN;
            }

            Some(Self {
                thread_hash,
                duplicate_ids,
            })
        } else {
            None
        }
    }
}

pub(crate) struct ThreadInfo;

impl ThreadInfo {
    pub fn serialize(thread_id: u32, ref_ids: &CheekyHashMap<bool>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(U32_LEN + ref_ids.len() * (1 + 16));
        buf.extend_from_slice(&thread_id.to_be_bytes());
        for (ref_id, is_message_id) in ref_ids {
            if *is_message_id && buf.len() > U32_LEN {
                // Place Message-id reference first
                let mut new_buf = Vec::with_capacity(U32_LEN + ref_ids.len() * (1 + 16));
                new_buf.extend_from_slice(&thread_id.to_be_bytes());
                new_buf.extend_from_slice(ref_id.as_bytes());
                new_buf.extend_from_slice(&buf[U32_LEN..]);
                buf = new_buf;
            } else {
                buf.extend_from_slice(ref_id.as_bytes());
            }
        }
        buf
    }
}
