/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::enums::DkimSignatureType;

impl DkimSignatureType {
    pub const fn algorithm(self) -> &'static str {
        match self {
            Self::Dkim1Ed25519Sha256 => "ed25519",
            Self::Dkim1RsaSha256 => "rsa",
        }
    }

    pub const fn hash(self) -> &'static str {
        match self {
            Self::Dkim1Ed25519Sha256 | Self::Dkim1RsaSha256 => "sha256",
        }
    }

    pub const fn version(self) -> &'static str {
        match self {
            Self::Dkim1Ed25519Sha256 | Self::Dkim1RsaSha256 => "1",
        }
    }
}
