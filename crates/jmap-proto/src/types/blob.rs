/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::parser::{JsonObjectParser, base32::JsonBase32Reader, json::Parser};
use types::blob::BlobId;

impl JsonObjectParser for BlobId {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut it = JsonBase32Reader::new(parser);
        BlobId::from_iter(&mut it).ok_or_else(|| it.error())
    }
}
