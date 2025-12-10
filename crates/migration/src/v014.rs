/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    SUBSPACE_INDEXES, U64_LEN,
    write::{AnyKey, key::KeySerializer},
};
use trc::AddContext;
use types::collection::Collection;

pub const SUBSPACE_BITMAP_ID: u8 = b'b';
pub const SUBSPACE_BITMAP_TAG: u8 = b'c';
pub const SUBSPACE_BITMAP_TEXT: u8 = b'v';
pub const SUBSPACE_FTS_INDEX: u8 = b'g';
pub const SUBSPACE_TELEMETRY_INDEX: u8 = b'w';

pub(crate) async fn migrate_v0_14(server: &Server) -> trc::Result<()> {
    /*

       - ContactField
       - CalendarField
       - EmailSubmissionField
       - CalendarNotificationField

    */

    todo!()
}

pub(crate) async fn migrate_indexes(server: &Server, account_id: u32) -> trc::Result<()> {
    /*

           EmailSubmissionField::UndoStatus => 41,
           EmailSubmissionField::EmailId => 83,
           EmailSubmissionField::ThreadId => 33,
           EmailSubmissionField::IdentityId => 95,
           EmailSubmissionField::SendAt => 24,

    */

    /*

           ContactField::Created => 2,
           ContactField::Updated => 3,
           ContactField::Text => 4,
    */

    /*

           CalendarField::Text => 1,
           CalendarField::Created => 2,
           CalendarField::Updated => 3,
           CalendarField::Start => 4,
           CalendarField::EventId => 5,
    */

    for (collection, fields) in [
        (Collection::EmailSubmission, &[41u8, 83, 33, 95, 24][..]),
        (Collection::ContactCard, &[2, 3, 4][..]),
        (Collection::CalendarEvent, &[1, 2, 3, 4][..]),
        (Collection::CalendarEventNotification, &[2, 5][..]),
    ] {
        for index in fields {
            server
                .store()
                .delete_range(
                    AnyKey {
                        subspace: SUBSPACE_INDEXES,
                        key: KeySerializer::new(U64_LEN * 3)
                            .write(account_id)
                            .write(u8::from(collection))
                            .write(*index)
                            .finalize(),
                    },
                    AnyKey {
                        subspace: SUBSPACE_INDEXES,
                        key: KeySerializer::new(U64_LEN * 4)
                            .write(account_id)
                            .write(u8::from(collection))
                            .write(*index)
                            .write(&[u8::MAX; 8][..])
                            .finalize(),
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }
    }

    Ok(())
}
