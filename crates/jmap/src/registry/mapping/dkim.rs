/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{
    ObjectResponse, RegistrySetResponse, ValidationResult, principal::validate_tenant_quota,
};
use common::config::smtp::auth::{DkimSigner, rsa_key_parse, simple_pem_parse};
use jmap_proto::error::set::SetError;
use mail_auth::{common::crypto::Ed25519Key, dkim::generate::DkimKeyPair};
use mail_builder::encoders::base64::base64_encode;
use pkcs8::Document;
use registry::{
    jmap::IntoValue,
    schema::{
        enums::{DkimSignatureType, TenantStorageQuota},
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
        let private_key = tokio::task::spawn_blocking(move || match key_type {
            DkimSignatureType::Dkim1RsaSha256 => {
                DkimKeyPair::generate_rsa(2048).map(|key| (key, "RSA PRIVATE KEY"))
            }
            DkimSignatureType::Dkim1Ed25519Sha256 => {
                DkimKeyPair::generate_ed25519().map(|key| (key, "PRIVATE KEY"))
            }
        })
        .await
        .map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .caused_by(trc::location!())
        })?;

        match private_key {
            Ok((private_key, pk_type)) => {
                let mut pem = format!("-----BEGIN {pk_type}-----\n").into_bytes();
                let mut lf_count = 65;
                for ch in base64_encode(private_key.private_key()).unwrap_or_default() {
                    pem.push(ch);
                    lf_count -= 1;
                    if lf_count == 0 {
                        pem.push(b'\n');
                        lf_count = 65;
                    }
                }
                if lf_count != 65 {
                    pem.push(b'\n');
                }
                pem.extend_from_slice(format!("-----END {pk_type}-----\n").as_bytes());

                let pk_value = DkimPrivateKey::Value(SecretTextValue {
                    secret: String::from_utf8(pem).unwrap_or_default(),
                });

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
