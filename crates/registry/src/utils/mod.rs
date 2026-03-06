/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::schema::prelude::{DkimPrivateKey, DkimSignature, Roles};
use types::id::Id;

pub mod account;
pub mod archived_item;
pub mod cron;
pub mod http;
pub mod report;
pub mod secret;
pub mod task;

impl Roles {
    pub fn role_ids(&self) -> Option<&[Id]> {
        match self {
            Roles::Default => None,
            Roles::Custom(custom_roles) => Some(custom_roles.role_ids.as_slice()),
        }
    }
}

impl DkimSignature {
    pub fn private_key(&self) -> &DkimPrivateKey {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(signature) => &signature.private_key,
            DkimSignature::Dkim1RsaSha256(signature) => &signature.private_key,
        }
    }

    pub fn private_key_mut(&mut self) -> &mut DkimPrivateKey {
        match self {
            DkimSignature::Dkim1Ed25519Sha256(signature) => &mut signature.private_key,
            DkimSignature::Dkim1RsaSha256(signature) => &mut signature.private_key,
        }
    }
}

impl DkimPrivateKey {
    pub async fn pem(&self) -> trc::Result<Cow<'_, str>> {
        match self {
            DkimPrivateKey::Value(value) => Ok(Cow::Borrowed(value.secret.as_str())),
            DkimPrivateKey::File(file) => file.secret().await.map(Cow::Owned),
            DkimPrivateKey::Generate => Err("Key is in invalid generate state".to_string()),
        }
        .map_err(|err| trc::DkimEvent::BuildError.reason(err))
    }
}
