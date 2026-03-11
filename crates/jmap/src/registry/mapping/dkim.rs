/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{
    ObjectResponse, RegistrySetResponse, ValidationResult, principal::validate_tenant_quota,
};
use common::{
    config::smtp::auth::{DkimSigner, rsa_key_parse, simple_pem_parse},
    network::dkim::generate_dkim_private_key,
};
use jmap_proto::error::set::SetError;
use mail_auth::common::crypto::Ed25519Key;
use mail_builder::encoders::base64::base64_encode;
use pkcs8::Document;
use registry::{
    jmap::IntoValue,
    schema::{
        enums::TenantStorageQuota,
        prelude::{MASKED_PASSWORD, Property},
        structs::{DkimPrivateKey, DkimSignature, SecretTextValue},
    },
};
use rsa::pkcs1::DecodeRsaPublicKey;

pub(crate) async fn validate_dkim_signature(
    set: &RegistrySetResponse<'_>,
    key: &mut DkimSignature,
    old_key: Option<&DkimSignature>,
) -> ValidationResult {
    let mut response = if old_key.is_none() {
        match validate_tenant_quota(set, TenantStorageQuota::MaxDkimKeys).await? {
            Ok(response) => response,
            Err(err) => {
                return Ok(Err(err));
            }
        }
    } else {
        ObjectResponse::default()
    };

    // Generate private key if requested
    let key_type = key.object_type();
    let pk = key.private_key_mut();
    if let Some(old_key) = old_key
        && matches!(pk, DkimPrivateKey::Value(value) if value.secret == MASKED_PASSWORD)
    {
        *pk = old_key.private_key().clone();
    }
    if pk == &DkimPrivateKey::Generate {
        match generate_dkim_private_key(key_type).await? {
            Ok(secret) => {
                let pk_value = DkimPrivateKey::Value(SecretTextValue { secret });

                response
                    .object
                    .insert(Property::PrivateKey, pk_value.clone().into_value());

                *pk = pk_value;
            }
            Err(err) => {
                return Ok(Err(SetError::forbidden().with_description(err.to_string())));
            }
        }
    }

    // Verify signature
    match DkimSigner::new("example.com".to_string(), key.clone()).await {
        Ok(_) => Ok(Ok(response)),
        Err(err) => Ok(Err(SetError::invalid_properties()
            .with_description(format!("Failed to build DKIM signature: {err}")))),
    }
}

pub async fn generate_dkim_public_key(key: &DkimSignature) -> trc::Result<String> {
    match key {
        DkimSignature::Dkim1RsaSha256(key) => key
            .private_key
            .pem()
            .await
            .and_then(|pem| rsa_key_parse(pem.as_bytes()))
            .and_then(|pk| {
                Document::from_pkcs1_der(&pk.public_key()).map_err(|err| {
                    trc::EventType::Dkim(trc::DkimEvent::BuildError)
                        .into_err()
                        .reason(err)
                })
            })
            .map(|pk| {
                String::from_utf8(base64_encode(pk.as_bytes()).unwrap_or_default())
                    .unwrap_or_default()
            }),
        DkimSignature::Dkim1Ed25519Sha256(key) => key
            .private_key
            .pem()
            .await
            .and_then(|pem| {
                simple_pem_parse(&pem).ok_or_else(|| {
                    trc::EventType::Dkim(trc::DkimEvent::BuildError)
                        .into_err()
                        .details("Failed to parse private key PEM")
                })
            })
            .and_then(|der| {
                Ed25519Key::from_pkcs8_maybe_unchecked_der(&der).map_err(|err| {
                    trc::EventType::Dkim(trc::DkimEvent::BuildError)
                        .into_err()
                        .reason(err)
                })
            })
            .map(|pk| {
                String::from_utf8(base64_encode(&pk.public_key()).unwrap_or_default())
                    .unwrap_or_default()
            }),
    }
}
