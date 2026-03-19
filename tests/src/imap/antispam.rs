/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{IMAPTest, ImapConnection};
use crate::{imap::Type, jmap::mail::delivery::SmtpConnection, smtp::session::VerifyResponse};
use common::{Server, manager::SPAM_TRAINER_KEY};
use imap_proto::ResponseType;
use spam_filter::modules::classifier::{SpamClassifier, SpamTrainer};
use store::{
    Deserialize, IterateParams, U32_LEN, U64_LEN, ValueKey,
    write::{AlignedBytes, Archive, BlobOp, ValueClass, key::DeserializeBigEndian},
};
use types::blob_hash::BlobHash;

pub async fn test(handle: &IMAPTest) {
    println!("Running Spam classifier tests...");
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.authenticate("sgd@example.com", "secret").await;

    let account_id = handle
        .server
        .directory()
        .email_to_id("sgd@example.com")
        .await
        .unwrap()
        .unwrap();

    // Make sure there are no training samples
    spam_delete_samples(&handle.server).await;
    assert_eq!(spam_training_samples(&handle.server).await.total_count, 0);

    // Train the classifier via APPEND
    imap.append("INBOX", HAM[0]).await;
    imap.append("Junk Mail", SPAM[0]).await;
    let samples = spam_training_samples(&handle.server).await;
    assert_eq!(samples.ham_count, 1);
    assert_eq!(samples.spam_count, 1);

    // Append two spam samples to "Drafts", then train the classifier via STORE and MOVE
    imap.append("Drafts", SPAM[1]).await;
    imap.append("Drafts", SPAM[2]).await;
    imap.send_ok("SELECT Drafts").await;
    imap.send_ok("STORE 1 +FLAGS ($Junk)").await;
    imap.send_ok("MOVE 2 \"Junk Mail\"").await;
    let samples = spam_training_samples(&handle.server).await;
    assert_eq!(samples.ham_count, 1);
    assert_eq!(samples.spam_count, 3);

    // Add the remaining messages via APPEND
    for message in HAM.iter().skip(1) {
        imap.append("INBOX", message).await;
    }
    for message in SPAM.iter().skip(3) {
        imap.append("Junk Mail", message).await;
    }
    let samples = spam_training_samples(&handle.server).await;
    assert_eq!(samples.ham_count, 10);
    assert_eq!(samples.spam_count, 10);
    assert_eq!(samples.samples.len(), 20);
    assert!(
        samples
            .samples
            .iter()
            .all(|s| s.account_id == account_id && s.remove.is_none())
    );

    // Train the classifier
    handle.server.spam_train(false).await.unwrap();
    let model = spam_classifier_model(&handle.server).await;
    assert_eq!(model.reservoir.ham.total_seen, 10);
    assert_eq!(model.reservoir.spam.total_seen, 10);
    assert_eq!(
        model.last_sample_expiry,
        samples.samples.iter().map(|s| s.until).max().unwrap()
    );
    assert_eq!(spam_training_samples(&handle.server).await.total_count, 20);
    assert!(handle.server.inner.data.spam_classifier.load().is_active());

    // Send 3 test emails
    for message in TEST {
        let mut lmtp = SmtpConnection::connect_port(11201).await;
        lmtp.ingest("bill@example.com", &["sgd@example.com"], message)
            .await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    imap.send_ok("SELECT INBOX").await;
    imap.send("FETCH 11 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: can someone explain")
        .assert_contains("X-Spam-Status: No")
        .assert_contains("PROB_HAM_HIGH");
    imap.send("FETCH 12 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: classifier test")
        .assert_contains("X-Spam-Status: No")
        .assert_contains("PROB_SPAM_UNCERTAIN");
    imap.send_ok("SELECT \"Junk Mail\"").await;
    imap.send("FETCH 10 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS ($Junk")
        .assert_contains("Subject: save up to")
        .assert_contains("X-Spam-Status: Yes")
        .assert_contains("PROB_SPAM_HIGH");
    imap.send_ok("MOVE 10 INBOX").await;
    let samples = spam_training_samples(&handle.server).await;
    assert_eq!(samples.ham_count, 11);
    assert_eq!(samples.spam_count, 10);

    // Make sure spam traps trigger spam classification
    let mut lmtp = SmtpConnection::connect_port(11201).await;
    lmtp.ingest("bill@example.com", &["spamtrap@example.com"], SPAM[4])
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let samples = spam_training_samples(&handle.server).await;
    assert_eq!(samples.ham_count, 11);
    assert_eq!(samples.spam_count, 11);
}

#[derive(Default, Debug)]
pub struct TrainingSamples {
    pub samples: Vec<TrainingSample>,
    pub spam_count: usize,
    pub ham_count: usize,
    pub total_count: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct TrainingSample {
    pub hash: BlobHash,
    pub account_id: u32,
    pub is_spam: bool,
    pub remove: Option<u64>,
    pub until: u64,
}

pub async fn spam_classifier_model(server: &Server) -> SpamTrainer {
    server
        .blob_store()
        .get_blob(SPAM_TRAINER_KEY, 0..usize::MAX)
        .await
        .and_then(|archive| match archive {
            Some(archive) => <Archive<AlignedBytes> as Deserialize>::deserialize(&archive)
                .and_then(|archive| archive.deserialize_untrusted::<SpamTrainer>())
                .map(Some),
            None => Ok(None),
        })
        .unwrap()
        .unwrap()
}

pub async fn spam_delete_samples(server: &Server) {
    let from_key = ValueKey {
        account_id: 0,
        collection: 0,
        document_id: 0,
        class: ValueClass::Blob(BlobOp::SpamSample {
            hash: BlobHash::default(),
            until: 0,
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
    server.store().delete_range(from_key, to_key).await.unwrap();
}

pub async fn spam_training_samples(server: &Server) -> TrainingSamples {
    let mut samples = TrainingSamples::default();
    let from_key = ValueKey {
        account_id: 0,
        collection: 0,
        document_id: 0,
        class: ValueClass::Blob(BlobOp::SpamSample {
            hash: BlobHash::default(),
            until: 0,
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
    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let until = key.deserialize_be_u64(1)?;
                let account_id = key.deserialize_be_u32(U64_LEN + 1)?;
                let hash =
                    BlobHash::try_from_hash_slice(key.get(U64_LEN + U32_LEN + 1..).ok_or_else(
                        || trc::Error::corrupted_key(key, value.into(), trc::location!()),
                    )?)
                    .unwrap();
                let (Some(is_spam), Some(hold)) = (value.first(), value.get(1)) else {
                    return Err(trc::Error::corrupted_key(
                        key,
                        value.into(),
                        trc::location!(),
                    ));
                };

                let do_remove = *hold == 0;
                let is_spam = *is_spam == 1;
                samples.samples.push(TrainingSample {
                    hash,
                    account_id,
                    is_spam,
                    remove: do_remove.then_some(until),
                    until,
                });
                if is_spam {
                    samples.spam_count += 1;
                } else {
                    samples.ham_count += 1;
                }
                samples.total_count += 1;

                Ok(true)
            },
        )
        .await
        .unwrap();

    samples
}
