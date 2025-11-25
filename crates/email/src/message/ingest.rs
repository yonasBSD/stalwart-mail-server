/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::crypto::{EncryptMessage, EncryptMessageError};
use crate::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::{INBOX_ID, JUNK_ID, UidMailbox},
    message::{
        crypto::EncryptionParams,
        index::{IndexMessage, extractors::VisitText},
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
use std::{borrow::Cow, cmp::Ordering, fmt::Write, time::Instant};
use std::{future::Future, hash::Hasher};
use store::{
    IndexKeyPrefix, IterateParams, U32_LEN, ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{
        AssignedId, AssignedIds, BatchBuilder, IndexPropertyClass, SearchIndex, TaskEpoch,
        TaskQueueClass, ValueClass, key::DeserializeBigEndian, now,
    },
};
use trc::{AddContext, MessageIngestEvent};
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::{ContactField, EmailField, MailboxField, PrincipalField},
    keyword::Keyword,
};
use utils::{cheeky_hash::CheekyHash, sanitize_email};

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
    pub blob_hash: Option<&'x BlobHash>,
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
        message_ids: &[CheekyHash],
    ) -> impl Future<Output = trc::Result<ThreadResult>> + Send;
    fn assign_email_ids(
        &self,
        account_id: u32,
        mailbox_ids: impl IntoIterator<Item = u32> + Sync + Send,
        generate_email_id: bool,
    ) -> impl Future<Output = trc::Result<impl Iterator<Item = u32> + 'static>> + Send;
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
                        && self
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
                                                .to_string()
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
        let mut message_ids = Vec::new();
        let thread_result = {
            let mut subject = "";
            for header in message.root_part().headers().iter().rev() {
                match &header.name {
                    HeaderName::MessageId => header.value.visit_text(|id| {
                        if !id.is_empty() {
                            if message_id.is_none() {
                                message_id = id.to_string().into();
                            }
                            message_ids.push(CheekyHash::new(id.as_bytes()));
                        }
                    }),
                    HeaderName::InReplyTo
                    | HeaderName::References
                    | HeaderName::ResentMessageId => {
                        header.value.visit_text(|id| {
                            if !id.is_empty() {
                                message_ids.push(CheekyHash::new(id.as_bytes()));
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
                        });
                    }
                    _ => (),
                }
            }

            message_ids.sort_unstable();
            message_ids.dedup();

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
                    params.blob_hash = None;

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
        let (blob_hash, blob_hold) = if let Some(blob_hash) = params.blob_hash {
            (blob_hash.clone(), None)
        } else {
            self.put_temporary_blob(account_id, raw_message.as_ref(), 60)
                .await
                .map(|(hash, op)| (hash, Some(op)))
                .caused_by(trc::location!())?
        };

        // Assign IMAP UIDs
        let mut mailbox_ids = Vec::with_capacity(params.mailbox_ids.len());
        let mut imap_uids = Vec::with_capacity(params.mailbox_ids.len());
        let mut ids = self
            .assign_email_ids(account_id, params.mailbox_ids.iter().copied(), true)
            .await
            .caused_by(trc::location!())?;
        let document_id = ids.next().unwrap();
        for (uid, mailbox_id) in ids.zip(params.mailbox_ids.iter().copied()) {
            mailbox_ids.push(UidMailbox::new(mailbox_id, uid));
            imap_uids.push(uid);
        }

        // Build write batch
        let mut batch = BatchBuilder::new();
        let mailbox_ids_event = mailbox_ids
            .iter()
            .map(|m| trc::Value::from(m.mailbox_id))
            .collect::<Vec<_>>();
        batch.with_account_id(account_id);

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

        let data = MessageData {
            mailboxes: mailbox_ids.into_boxed_slice(),
            keywords: params.keywords.into_boxed_slice(),
            thread_id,
            size: (message.raw_message.len() + extra_headers.len()) as u32,
        };

        batch
            .with_collection(Collection::Email)
            .with_document(document_id)
            .index_message(
                tenant_id,
                message,
                extra_headers.into_bytes(),
                extra_headers_parsed,
                blob_hash.clone(),
                data,
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
                ValueClass::TaskQueue(TaskQueueClass::UpdateIndex {
                    index: SearchIndex::Email,
                    due: TaskEpoch::now(),
                    is_insert: true,
                }),
                vec![],
            );

        if let Some(blob_hold) = blob_hold {
            batch.clear(blob_hold);
        }

        // Merge threads if necessary
        if let Some(merge_threads) = MergeThreadIds::new(thread_result).serialize() {
            batch.set(
                ValueClass::TaskQueue(TaskQueueClass::MergeThreads {
                    due: TaskEpoch::now(),
                }),
                merge_threads,
            );
        }

        // Request spam training
        if let Some(learn_spam) = train_spam {
            batch.set(
                ValueClass::TaskQueue(TaskQueueClass::BayesTrain {
                    due: TaskEpoch::now(),
                    learn_spam,
                }),
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
            BlobId = blob_hash.to_hex(),
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
                hash: blob_hash,
                class: BlobClass::Linked {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                },
                section: None,
            },
            size: raw_message_len as usize,
            imap_uids,
        })
    }

    async fn find_thread_id(
        &self,
        account_id: u32,
        thread_name: &str,
        message_ids: &[CheekyHash],
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
        let mut thread_merge = ThreadMerge::new();
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
                        let references = value.get(U32_LEN..).unwrap_or_default();

                        if has_message_id(message_ids, references) {
                            let document_id = key.deserialize_be_u32(document_id_pos)?;
                            let thread_id = value.deserialize_be_u32(0)?;

                            if message_ids.len() == 1
                                || (message_ids.len() == references.len() / CheekyHash::HASH_SIZE
                                    && references
                                        .chunks_exact(CheekyHash::HASH_SIZE)
                                        .zip(message_ids.iter())
                                        .all(|(a, b)| a == b.as_raw_bytes()))
                            {
                                result.duplicate_ids.push(document_id);
                            }

                            thread_merge.add(thread_id, document_id);
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        match thread_merge.num_thread_ids() {
            0 => Ok(result),
            1 => {
                // Happy path, only one thread id
                result.thread_id = thread_merge.thread_ids().next().copied();
                Ok(result)
            }
            _ => {
                // Multiple thread ids that this message belongs to, merge them
                let thread_merge = thread_merge.merge();
                result.merge_ids = thread_merge.merge_ids;
                result.thread_id = Some(thread_merge.thread_id);
                Ok(result)
            }
        }
    }

    async fn assign_email_ids(
        &self,
        account_id: u32,
        mailbox_ids: impl IntoIterator<Item = u32> + Sync + Send,
        generate_email_id: bool,
    ) -> trc::Result<impl Iterator<Item = u32> + 'static> {
        // Increment UID next
        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);

        let mut expected_ids = 0;
        if generate_email_id {
            batch
                .with_collection(Collection::Email)
                .add_and_get(ValueClass::DocumentId, 1);
            expected_ids += 1;
        }

        batch.with_collection(Collection::Mailbox);

        for mailbox_id in mailbox_ids {
            batch
                .with_document(mailbox_id)
                .add_and_get(MailboxField::UidCounter, 1);
            expected_ids += 1;
        }

        let ids = if expected_ids > 0 {
            self.core.storage.data.write(batch.build_all()).await?
        } else {
            AssignedIds::default()
        };
        if ids.ids.len() == expected_ids {
            Ok(ids.ids.into_iter().map(|id| match id {
                AssignedId::Counter(id) => id as u32,
                AssignedId::ChangeId(_) => unreachable!(),
            }))
        } else {
            Err(trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "No all document ids were generated"))
        }
    }

    fn email_bayes_can_train(&self, access_token: &AccessToken) -> bool {
        self.core.spam.bayes.as_ref().is_some_and(|bayes| {
            bayes.account_classify && access_token.has_permission(Permission::SpamFilterTrain)
        })
    }
}

fn has_message_id(a: &[CheekyHash], b: &[u8]) -> bool {
    let mut i = 0;
    let mut j = 0;

    let a_len = a.len();
    let b_len = b.len() / CheekyHash::HASH_SIZE;

    while i < a_len && j < b_len {
        match a[i]
            .as_raw_bytes()
            .as_slice()
            .cmp(&b[j * CheekyHash::HASH_SIZE..(j + 1) * CheekyHash::HASH_SIZE])
        {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }

    false
}

impl IngestSource<'_> {
    pub fn is_smtp(&self) -> bool {
        matches!(self, Self::Smtp { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeThreadIds<T> {
    pub thread_hash: CheekyHash,
    pub merge_ids: T,
}

impl MergeThreadIds<Vec<u32>> {
    pub(crate) fn new(thread_result: ThreadResult) -> Self {
        Self {
            thread_hash: thread_result.thread_hash,
            merge_ids: thread_result.merge_ids,
        }
    }

    pub(crate) fn serialize(&self) -> Option<Vec<u8>> {
        if !self.merge_ids.is_empty() {
            let mut buf =
                Vec::with_capacity(self.thread_hash.len() + self.merge_ids.len() * U32_LEN);
            buf.extend_from_slice(self.thread_hash.as_bytes());
            for id in &self.merge_ids {
                buf.extend_from_slice(&id.to_be_bytes());
            }
            Some(buf)
        } else {
            None
        }
    }
}

impl MergeThreadIds<AHashSet<u32>> {
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if !bytes.is_empty() {
            let thread_hash = CheekyHash::deserialize(bytes)?;
            let mut merge_ids =
                AHashSet::with_capacity(((bytes.len() - thread_hash.len()) / U32_LEN) + 1);
            let mut start_offset = thread_hash.len();

            while let Some(id_bytes) = bytes.get(start_offset..start_offset + U32_LEN) {
                merge_ids.insert(u32::from_be_bytes(id_bytes.try_into().ok()?));
                start_offset += U32_LEN;
            }

            Some(Self {
                thread_hash,
                merge_ids,
            })
        } else {
            None
        }
    }
}

impl std::hash::Hash for MergeThreadIds<AHashSet<u32>> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.thread_hash.hash(state);
        self.merge_ids.len().hash(state);
    }
}

pub(crate) struct ThreadInfo;

impl ThreadInfo {
    pub fn serialize(thread_id: u32, ref_ids: &[CheekyHash]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(U32_LEN + 1 + ref_ids.len() * CheekyHash::HASH_SIZE);
        buf.extend_from_slice(&thread_id.to_be_bytes());
        for ref_id in ref_ids {
            buf.extend_from_slice(ref_id.as_raw_bytes());
        }
        buf
    }
}

pub struct ThreadMerge {
    entries: AHashMap<u32, Vec<u32>>,
}

pub struct ThreadMergeResult {
    pub thread_id: u32,
    pub merge_ids: Vec<u32>,
}

impl ThreadMerge {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: AHashMap::with_capacity(8),
        }
    }

    pub fn add(&mut self, thread_id: u32, document_id: u32) {
        self.entries.entry(thread_id).or_default().push(document_id);
    }

    pub fn num_thread_ids(&self) -> usize {
        self.entries.len()
    }

    pub fn thread_ids(&self) -> impl Iterator<Item = &u32> {
        self.entries.keys()
    }

    pub fn thread_groups(&self) -> impl Iterator<Item = (&u32, &Vec<u32>)> {
        self.entries.iter()
    }

    pub fn merge_thread_id(&self) -> u32 {
        let mut max_thread_id = u32::MAX;
        let mut max_count = 0;

        for (thread_id, ids) in &self.entries {
            match ids.len().cmp(&max_count) {
                Ordering::Greater => {
                    max_count = ids.len();
                    max_thread_id = *thread_id;
                }
                Ordering::Equal => {
                    if *thread_id < max_thread_id {
                        max_thread_id = *thread_id;
                    }
                }
                Ordering::Less => (),
            }
        }

        max_thread_id
    }

    pub fn merge(self) -> ThreadMergeResult {
        let mut max_thread_id = u32::MAX;
        let mut max_count = 0;
        let mut merge_ids = Vec::with_capacity(self.entries.len());

        for (thread_id, ids) in self.entries {
            match ids.len().cmp(&max_count) {
                Ordering::Greater => {
                    max_count = ids.len();
                    max_thread_id = thread_id;
                }
                Ordering::Equal => {
                    if thread_id < max_thread_id {
                        max_thread_id = thread_id;
                    }
                }
                Ordering::Less => (),
            }
            merge_ids.push(thread_id);
        }

        ThreadMergeResult {
            thread_id: max_thread_id,
            merge_ids,
        }
    }
}
