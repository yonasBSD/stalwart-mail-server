/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use crate::network::acme::directory::AcmeRequestBuilder;
use crate::network::acme::{
    AcmeError, AcmeResult, AuthStatus, ChallengeType, Identifier, OrderStatus, ParsedCert, PemCert,
};
use crate::{KV_ACME, Server};
use chrono::{TimeZone, Utc};
use futures::future::try_join_all;
use rcgen::{CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use store::dispatch::lookup::KeyValue;
use trc::AcmeEvent;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{GeneralName, ParsedExtension};

const HOSTNAMES: &[&str] = &["mta-sts", "ua-auto-config", "autoconfig", "autodiscover"];

impl AcmeRequestBuilder {
    pub async fn renew(
        &self,
        server: &Server,
        domain: &str,
        hostnames: &[String],
    ) -> AcmeResult<PemCert> {
        let domains = if hostnames.is_empty() {
            if matches!(
                self.challenge,
                ChallengeType::Dns01 | ChallengeType::DnsPersist01
            ) {
                vec![format!("*.{domain}")]
            } else {
                server
                    .core
                    .network
                    .server_name
                    .strip_suffix(domain)
                    .and_then(|host| host.strip_suffix("."))
                    .map(|h| h.to_string())
                    .into_iter()
                    .chain(
                        HOSTNAMES
                            .iter()
                            .map(|hostname| format!("{hostname}.{domain}")),
                    )
                    .collect()
            }
        } else {
            hostnames
                .iter()
                .map(|hostname| format!("{hostname}.{domain}"))
                .collect()
        };

        let mut params = CertificateParams::new(domains.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params)
            .map_err(|err| AcmeError::Crypto(format!("Failed to generate certificate: {}", err)))?;
        let response = self.new_order(domains.clone()).await?;
        let order_url = response.location;
        let mut order = response.body;
        let mut retry_after = None;

        loop {
            match order.status {
                OrderStatus::Pending => {
                    let auth_futures = order
                        .authorizations
                        .iter()
                        .map(|url| self.authorize(server, url));
                    try_join_all(auth_futures).await?;
                    trc::event!(
                        Acme(AcmeEvent::AuthCompleted),
                        Url = self.directory.new_order.to_string(),
                        Hostname = domains.as_slice(),
                    );
                    let response = self.order(&order_url).await?;
                    order = response.body;
                    retry_after = response.retry_after;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        trc::event!(
                            Acme(AcmeEvent::OrderProcessing),
                            Url = self.directory.new_order.to_string(),
                            Hostname = domains.as_slice(),
                            Total = i,
                        );

                        tokio::time::sleep(
                            retry_after.unwrap_or_else(|| Duration::from_secs(1u64 << i)),
                        )
                        .await;
                        let response = self
                            .order(&order_url)
                            .await?
                            .assert_reasonable_retry_after()?;
                        order = response.body;
                        retry_after = response.retry_after;
                        if order.status != OrderStatus::Processing {
                            break;
                        }
                    }
                    if order.status == OrderStatus::Processing {
                        return Err(AcmeError::OrderTimeout);
                    }
                }
                OrderStatus::Ready => {
                    trc::event!(
                        Acme(AcmeEvent::OrderReady),
                        Url = self.directory.new_order.to_string(),
                        Hostname = domains.as_slice(),
                    );

                    let csr = cert.serialize_request_der().map_err(|err| {
                        AcmeError::Crypto(format!("Failed to serialize CSR: {}", err))
                    })?;
                    order = self.finalize(order.finalize, csr).await?.body;
                }
                OrderStatus::Valid { certificate } => {
                    trc::event!(
                        Acme(AcmeEvent::OrderValid),
                        Url = self.directory.new_order.to_string(),
                        Hostname = domains.as_slice(),
                    );

                    let certificate = self.certificate(certificate).await?;

                    return Ok(PemCert {
                        certificate,
                        private_key: cert.serialize_private_key_pem(),
                    });
                }
                OrderStatus::Invalid => {
                    return Err(AcmeError::OrderInvalid);
                }
            }
        }
    }

    async fn authorize(&self, server: &Server, url: &String) -> AcmeResult<()> {
        let response = self.auth(url).await?.assert_reasonable_retry_after()?;
        let mut retry_after = response.retry_after;
        let auth = response.body;

        let (domain, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                let Identifier::Dns(domain) = auth.identifier;

                trc::event!(
                    Acme(AcmeEvent::AuthStart),
                    Hostname = domain.to_string(),
                    Type = self.challenge.as_str(),
                    Url = self.directory.new_order.to_string(),
                );

                let challenge = auth
                    .challenges
                    .iter()
                    .find(|c| c.typ == self.challenge)
                    .ok_or(AcmeError::ChallengeNotSupported {
                        requested: self.challenge,
                        supported: auth.challenges.clone(),
                    })?;

                match &self.challenge {
                    ChallengeType::TlsAlpn01 => {
                        server
                            .in_memory_store()
                            .key_set(
                                KeyValue::with_prefix(
                                    KV_ACME,
                                    &domain,
                                    self.tls_alpn_key(challenge, domain.clone())?,
                                )
                                .expires(3600),
                            )
                            .await?;
                    }
                    ChallengeType::Http01 => {
                        server
                            .in_memory_store()
                            .key_set(
                                KeyValue::with_prefix(
                                    KV_ACME,
                                    &challenge.token,
                                    self.http_proof(challenge)?,
                                )
                                .expires(3600),
                            )
                            .await?;
                    }
                    ChallengeType::Dns01 => {
                        let todo = "fix";
                        todo!()
                        /*let dns_proof = self.dns_proof(challenge)?;
                        let domain = domain.strip_prefix("*.").unwrap_or(&domain);
                        let name = format!("_acme-challenge.{}", domain);
                        let origin = origin
                            .as_deref()
                            .or_else(|| psl::domain_str(domain))
                            .unwrap_or(domain)
                            .to_string();

                        // First try deleting the record
                        if let Err(err) = updater.delete(&name, &origin, DnsRecordType::TXT).await {
                            // Errors are expected if the record does not exist
                            trc::event!(
                                Dns(DnsEvent::RecordDeletionFailed),
                                Hostname = name.to_string(),
                                Reason = err.to_string(),
                                Details = origin.to_string(),
                                Url = self.directory.new_order.to_string(),
                            );
                        }

                        // Create the record
                        if let Err(err) = updater
                            .create(
                                &name,
                                DnsRecord::TXT {
                                    content: dns_proof.clone(),
                                },
                                *ttl,
                                &origin,
                            )
                            .await
                        {
                            return Err(EventType::Dns(DnsEvent::RecordCreationFailed)
                                .ctx(trc::Key::Id, self.id.to_string())
                                .ctx(trc::Key::Hostname, name)
                                .ctx(trc::Key::Details, origin)
                                .reason(err));
                        }

                        trc::event!(
                            Dns(DnsEvent::RecordCreated),
                            Hostname = name.to_string(),
                            Details = origin.to_string(),
                            Url = self.directory.new_order.to_string(),
                        );

                        // Wait for changes to propagate
                        let wait_until = Instant::now() + *propagation_timeout;
                        let mut did_propagate = false;
                        while Instant::now() < wait_until {
                            match self.core.smtp.resolvers.dns.txt_raw_lookup(&name).await {
                                Ok(result) => {
                                    let result = std::str::from_utf8(&result).unwrap_or_default();
                                    if result.contains(&dns_proof) {
                                        did_propagate = true;
                                        break;
                                    } else {
                                        trc::event!(
                                            Dns(DnsEvent::RecordNotPropagated),
                                            Url = self.directory.new_order.to_string(),
                                            Hostname = name.to_string(),
                                            Details = origin.to_string(),
                                            Result = result.to_string(),
                                            Value = dns_proof.to_string(),
                                        );
                                    }
                                }
                                Err(err) => {
                                    trc::event!(
                                        Dns(DnsEvent::RecordLookupFailed),
                                        Url = self.directory.new_order.to_string(),
                                        Hostname = name.to_string(),
                                        Details = origin.to_string(),
                                        Reason = err.to_string(),
                                    );
                                }
                            }

                            tokio::time::sleep(*polling_interval).await;
                        }

                        if did_propagate {
                            trc::event!(
                                Dns(DnsEvent::RecordPropagated),
                                Url = self.directory.new_order.to_string(),
                                Hostname = name.to_string(),
                                Details = origin.to_string(),
                            );
                        } else {
                            trc::event!(
                                Dns(DnsEvent::RecordPropagationTimeout),
                                Url = self.directory.new_order.to_string(),
                                Hostname = name.to_string(),
                                Details = origin.to_string(),
                            );
                        }*/
                    }
                    ChallengeType::DnsPersist01 => return Ok(()),
                    ChallengeType::Unknown => unreachable!(),
                }

                self.challenge(&challenge.url).await?;
                (domain, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => {
                return Err(AcmeError::AuthInvalid(auth.status));
            }
        };

        for i in 0u64..5 {
            tokio::time::sleep(retry_after.unwrap_or_else(|| Duration::from_secs(1u64 << i))).await;
            let response = self.auth(url).await?.assert_reasonable_retry_after()?;
            retry_after = response.retry_after;

            match response.body.status {
                AuthStatus::Pending => {
                    trc::event!(
                        Acme(AcmeEvent::AuthPending),
                        Hostname = domain.to_string(),
                        Url = self.directory.new_order.to_string(),
                        Total = i,
                    );

                    self.challenge(&challenge_url).await?
                }
                AuthStatus::Valid => {
                    trc::event!(
                        Acme(AcmeEvent::AuthValid),
                        Hostname = domain.to_string(),
                        Url = self.directory.new_order.to_string(),
                    );

                    return Ok(());
                }
                _ => {
                    return Err(AcmeError::AuthInvalid(response.body.status));
                }
            }
        }

        Err(AcmeError::AuthTimeout)
    }
}

impl ParsedCert {
    pub fn parse(certificate: impl AsRef<[u8]>) -> AcmeResult<ParsedCert> {
        pem::parse_many(certificate)
            .map_err(|err| AcmeError::Crypto(format!("Failed to parse PEM: {}", err)))
            .and_then(|pems| {
                pems.into_iter()
                    .next()
                    .ok_or_else(|| AcmeError::Crypto("No certificates found in PEM".to_string()))
            })
            .and_then(|der| {
                parse_x509_certificate(der.contents())
                    .map_err(|err| {
                        AcmeError::Crypto(format!("Failed to parse X.509 certificate: {}", err))
                    })
                    .and_then(|(_, cert)| {
                        // Add CNs and SANs to the list of names
                        let mut names: BTreeSet<String> = BTreeSet::new();
                        for name in cert.subject().iter_common_name() {
                            if let Ok(name) = name.as_str() {
                                names.insert(name.into());
                            }
                        }
                        for ext in cert.extensions() {
                            if let ParsedExtension::SubjectAlternativeName(san) =
                                ext.parsed_extension()
                            {
                                for name in &san.general_names {
                                    let name = match name {
                                        GeneralName::DNSName(name) => (*name).into(),
                                        GeneralName::IPAddress(ip) => match ip.len() {
                                            4 => Ipv4Addr::from(<[u8; 4]>::try_from(*ip).unwrap())
                                                .to_string(),
                                            16 => {
                                                Ipv6Addr::from(<[u8; 16]>::try_from(*ip).unwrap())
                                                    .to_string()
                                            }
                                            _ => continue,
                                        },
                                        _ => {
                                            continue;
                                        }
                                    };
                                    names.insert(name);
                                }
                            }
                        }

                        Ok(ParsedCert {
                            sans: names.into_iter().collect(),
                            issuer: cert.tbs_certificate.issuer().to_string(),
                            valid_not_before: Utc
                                .timestamp_opt(
                                    cert.tbs_certificate.validity().not_before.timestamp(),
                                    0,
                                )
                                .single()
                                .ok_or_else(|| {
                                    AcmeError::Crypto(
                                        "Certificate not_before time is out of range".to_string(),
                                    )
                                })?,
                            valid_not_after: Utc
                                .timestamp_opt(
                                    cert.tbs_certificate.validity().not_after.timestamp(),
                                    0,
                                )
                                .single()
                                .ok_or_else(|| {
                                    AcmeError::Crypto(
                                        "Certificate not_after time is out of range".to_string(),
                                    )
                                })?,
                        })
                    })
            })
    }
}
