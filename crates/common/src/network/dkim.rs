/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_auth::dkim::generate::DkimKeyPair;
use mail_builder::encoders::base64::base64_encode;
use registry::schema::enums::DkimSignatureType;

pub async fn generate_dkim_private_key(
    key_type: DkimSignatureType,
) -> trc::Result<Result<String, String>> {
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

    Ok(private_key
        .map(|(private_key, pk_type)| {
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

            String::from_utf8(pem).unwrap_or_default()
        })
        .map_err(|err| err.to_string()))
}
