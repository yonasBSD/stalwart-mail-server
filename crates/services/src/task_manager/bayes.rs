/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::message::metadata::MessageMetadata;
use mail_parser::MessageParser;
use spam_filter::{
    SpamFilterInput, analysis::init::SpamFilterInit, modules::bayes::BayesClassifier,
};
use std::time::Instant;
use trc::{SpamEvent, TaskQueueEvent};
use types::{collection::Collection, field::EmailField};

pub trait BayesTrainTask: Sync + Send {
    fn bayes_train(
        &self,
        account_id: u32,
        document_id: u32,
        learn_spam: bool,
    ) -> impl Future<Output = bool> + Send;
}

impl BayesTrainTask for Server {
    async fn bayes_train(&self, account_id: u32, document_id: u32, learn_spam: bool) -> bool {
        let op_start = Instant::now();
        // Obtain metadata
        let metadata_ = match self
            .archive_by_property(
                account_id,
                Collection::Email,
                document_id,
                EmailField::Metadata.into(),
            )
            .await
        {
            Ok(Some(metadata)) => metadata,
            Ok(None) => {
                trc::event!(
                    TaskQueue(TaskQueueEvent::MetadataNotFound),
                    AccountId = account_id,
                    Collection = Collection::Email,
                    DocumentId = document_id,
                );
                return false;
            }
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                return false;
            }
        };

        let metadata = match metadata_.unarchive::<MessageMetadata>() {
            Ok(metadata) => metadata,
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                return false;
            }
        };

        // Obtain raw message
        match self
            .blob_store()
            .get_blob(metadata.blob_hash.0.as_slice(), 0..usize::MAX)
            .await
        {
            Ok(Some(raw_message)) => {
                // Train bayes classifier for account
                self.bayes_train_if_balanced(
                    &self.spam_filter_init(SpamFilterInput::from_account_message(
                        &MessageParser::new().parse(&raw_message).unwrap_or_default(),
                        account_id,
                        0,
                    )),
                    learn_spam,
                )
                .await;

                trc::event!(
                    Spam(SpamEvent::TrainAccount),
                    AccountId = account_id,
                    Collection = Collection::Email,
                    DocumentId = document_id,
                    Details = if learn_spam { "spam" } else { "ham" },
                    Elapsed = op_start.elapsed(),
                );
                true
            }
            Ok(None) => {
                trc::event!(
                    TaskQueue(TaskQueueEvent::BlobNotFound),
                    AccountId = account_id,
                    DocumentId = document_id,
                    BlobId = metadata.blob_hash.0.as_slice(),
                );
                false
            }
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                false
            }
        }
    }
}
