// Adapted from rustls-acme (https://github.com/FlorianUekermann/rustls-acme), licensed under MIT/Apache-2.0.

use chrono::{DateTime, TimeZone, Utc};

use compact_str::CompactString;
use dns_update::{DnsRecord, DnsRecordType};
use futures::future::try_join_all;
use rcgen::{CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::dispatch::lookup::KeyValue;
use trc::{AcmeEvent, EventType};
use x509_parser::parse_x509_certificate;

use crate::listener::acme::ChallengeSettings;
use crate::listener::acme::directory::Identifier;
use crate::{KV_ACME, Server};

use super::AcmeProvider;
use super::directory::{Account, AuthStatus, Directory, OrderStatus};

impl Server {
    pub(crate) async fn process_cert(
        &self,
        provider: &AcmeProvider,
        pem: Vec<u8>,
        cached: bool,
    ) -> trc::Result<Duration> {
        let (cert, validity) = parse_cert(&pem)?;

        self.set_cert(provider, Arc::new(cert));

        let renew_at = (validity[1] - provider.renew_before - Utc::now())
            .max(chrono::Duration::zero())
            .to_std()
            .unwrap_or_default();
        let renewal_date = validity[1] - provider.renew_before;

        trc::event!(
            Acme(AcmeEvent::ProcessCert),
            Id = provider.id.to_string(),
            Hostname = provider.domains.as_slice(),
            ValidFrom = trc::Value::Timestamp(validity[0].timestamp() as u64),
            ValidTo = trc::Value::Timestamp(validity[1].timestamp() as u64),
            Due = trc::Value::Timestamp(renewal_date.timestamp() as u64),
        );

        if !cached {
            self.store_cert(provider, &pem).await?;
        }

        Ok(renew_at)
    }

    pub async fn renew(&self, provider: &AcmeProvider) -> trc::Result<Duration> {
        let mut backoff = 0;
        loop {
            match self.order(provider).await {
                Ok(pem) => return self.process_cert(provider, pem, false).await,
                Err(err)
                    if !err.matches(EventType::Acme(AcmeEvent::OrderInvalid)) && backoff < 9 =>
                {
                    trc::event!(
                        Acme(AcmeEvent::RenewBackoff),
                        Id = provider.id.to_string(),
                        Hostname = provider.domains.as_slice(),
                        Total = backoff,
                        NextRetry = 1 << backoff,
                        CausedBy = err,
                    );
                    backoff += 1;
                    tokio::time::sleep(Duration::from_secs(1 << backoff)).await;
                }
                Err(err) => {
                    return Err(err
                        .details("Failed to renew certificate")
                        .ctx_unique(trc::Key::Id, provider.id.to_string())
                        .ctx_unique(trc::Key::Hostname, provider.domains.as_slice()));
                }
            }
        }
    }

    async fn order(&self, provider: &AcmeProvider) -> trc::Result<Vec<u8>> {
        let directory = Directory::discover(&provider.directory_url).await?;
        let account = Account::create_with_keypair(directory, provider).await?;

        let mut params = CertificateParams::new(provider.domains.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params).map_err(|err| {
            EventType::Acme(AcmeEvent::Error)
                .caused_by(trc::location!())
                .reason(err)
        })?;

        let (order_url, mut order) = account.new_order(provider.domains.clone()).await?;
        loop {
            match order.status {
                OrderStatus::Pending => {
                    let auth_futures = order
                        .authorizations
                        .iter()
                        .map(|url| self.authorize(provider, &account, url));
                    try_join_all(auth_futures).await?;
                    trc::event!(
                        Acme(AcmeEvent::AuthCompleted),
                        Id = provider.id.to_string(),
                        Hostname = provider.domains.as_slice(),
                    );
                    order = account.order(&order_url).await?;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        trc::event!(
                            Acme(AcmeEvent::OrderProcessing),
                            Id = provider.id.to_string(),
                            Hostname = provider.domains.as_slice(),
                            Total = i,
                        );

                        tokio::time::sleep(Duration::from_secs(1u64 << i)).await;
                        order = account.order(&order_url).await?;
                        if order.status != OrderStatus::Processing {
                            break;
                        }
                    }
                    if order.status == OrderStatus::Processing {
                        return Err(EventType::Acme(AcmeEvent::Error)
                            .caused_by(trc::location!())
                            .details("Order processing timed out"));
                    }
                }
                OrderStatus::Ready => {
                    trc::event!(
                        Acme(AcmeEvent::OrderReady),
                        Id = provider.id.to_string(),
                        Hostname = provider.domains.as_slice(),
                    );

                    let csr = cert.serialize_request_der().map_err(|err| {
                        EventType::Acme(AcmeEvent::Error)
                            .caused_by(trc::location!())
                            .reason(err)
                    })?;
                    order = account.finalize(order.finalize, csr).await?
                }
                OrderStatus::Valid { certificate } => {
                    trc::event!(
                        Acme(AcmeEvent::OrderValid),
                        Id = provider.id.to_string(),
                        Hostname = provider.domains.as_slice(),
                    );

                    let pem = [
                        &cert.serialize_private_key_pem(),
                        "\n",
                        &account.certificate(certificate).await?,
                    ]
                    .concat();
                    return Ok(pem.into_bytes());
                }
                OrderStatus::Invalid => {
                    return Err(EventType::Acme(AcmeEvent::OrderInvalid).into_err());
                }
            }
        }
    }

    async fn authorize(
        &self,
        provider: &AcmeProvider,
        account: &Account,
        url: &String,
    ) -> trc::Result<()> {
        let auth = account.auth(url).await?;
        let (domain, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                let Identifier::Dns(domain) = auth.identifier;
                let challenge_type = provider.challenge.challenge_type();

                trc::event!(
                    Acme(AcmeEvent::AuthStart),
                    Hostname = domain.to_string(),
                    Type = challenge_type.as_str(),
                    Id = provider.id.to_string(),
                );

                let challenge = auth
                    .challenges
                    .iter()
                    .find(|c| c.typ == challenge_type)
                    .ok_or(
                        EventType::Acme(AcmeEvent::OrderInvalid)
                            .into_err()
                            .details("Challenge not supported by ACME provider")
                            .ctx(trc::Key::Id, provider.id.to_string())
                            .ctx(trc::Key::Type, challenge_type.as_str())
                            .ctx(
                                trc::Key::Contents,
                                auth.challenges
                                    .iter()
                                    .map(|c| {
                                        trc::Value::String(CompactString::const_new(c.typ.as_str()))
                                    })
                                    .collect::<Vec<_>>(),
                            ),
                    )?;

                match &provider.challenge {
                    ChallengeSettings::TlsAlpn01 => {
                        self.in_memory_store()
                            .key_set(
                                KeyValue::with_prefix(
                                    KV_ACME,
                                    &domain,
                                    account.tls_alpn_key(challenge, domain.clone())?,
                                )
                                .expires(3600),
                            )
                            .await?;
                    }
                    ChallengeSettings::Http01 => {
                        self.in_memory_store()
                            .key_set(
                                KeyValue::with_prefix(
                                    KV_ACME,
                                    &challenge.token,
                                    account.http_proof(challenge)?,
                                )
                                .expires(3600),
                            )
                            .await?;
                    }
                    ChallengeSettings::Dns01 {
                        updater,
                        origin,
                        polling_interval,
                        propagation_timeout,
                        ttl,
                    } => {
                        let dns_proof = account.dns_proof(challenge)?;
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
                                Acme(AcmeEvent::DnsRecordDeletionFailed),
                                Hostname = name.to_string(),
                                Reason = err.to_string(),
                                Details = origin.to_string(),
                                Id = provider.id.to_string(),
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
                            return Err(EventType::Acme(AcmeEvent::DnsRecordCreationFailed)
                                .ctx(trc::Key::Id, provider.id.to_string())
                                .ctx(trc::Key::Hostname, name)
                                .ctx(trc::Key::Details, origin)
                                .reason(err));
                        }

                        trc::event!(
                            Acme(AcmeEvent::DnsRecordCreated),
                            Hostname = name.to_string(),
                            Details = origin.to_string(),
                            Id = provider.id.to_string(),
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
                                            Acme(AcmeEvent::DnsRecordNotPropagated),
                                            Id = provider.id.to_string(),
                                            Hostname = name.to_string(),
                                            Details = origin.to_string(),
                                            Result = result.to_string(),
                                            Value = dns_proof.to_string(),
                                        );
                                    }
                                }
                                Err(err) => {
                                    trc::event!(
                                        Acme(AcmeEvent::DnsRecordLookupFailed),
                                        Id = provider.id.to_string(),
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
                                Acme(AcmeEvent::DnsRecordPropagated),
                                Id = provider.id.to_string(),
                                Hostname = name.to_string(),
                                Details = origin.to_string(),
                            );
                        } else {
                            trc::event!(
                                Acme(AcmeEvent::DnsRecordPropagationTimeout),
                                Id = provider.id.to_string(),
                                Hostname = name.to_string(),
                                Details = origin.to_string(),
                            );
                        }
                    }
                }

                account.challenge(&challenge.url).await?;
                (domain, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => {
                return Err(EventType::Acme(AcmeEvent::AuthError)
                    .into_err()
                    .ctx(trc::Key::Id, provider.id.to_string())
                    .ctx(trc::Key::Details, auth.status.as_str()));
            }
        };

        for i in 0u64..5 {
            tokio::time::sleep(Duration::from_secs(1u64 << i)).await;
            let auth = account.auth(url).await?;
            match auth.status {
                AuthStatus::Pending => {
                    trc::event!(
                        Acme(AcmeEvent::AuthPending),
                        Hostname = domain.to_string(),
                        Id = provider.id.to_string(),
                        Total = i,
                    );

                    account.challenge(&challenge_url).await?
                }
                AuthStatus::Valid => {
                    trc::event!(
                        Acme(AcmeEvent::AuthValid),
                        Hostname = domain.to_string(),
                        Id = provider.id.to_string(),
                    );

                    return Ok(());
                }
                _ => {
                    return Err(EventType::Acme(AcmeEvent::AuthError)
                        .into_err()
                        .ctx(trc::Key::Id, provider.id.to_string())
                        .ctx(trc::Key::Details, auth.status.as_str()));
                }
            }
        }
        Err(EventType::Acme(AcmeEvent::AuthTooManyAttempts)
            .into_err()
            .ctx(trc::Key::Id, provider.id.to_string())
            .ctx(trc::Key::Hostname, domain))
    }
}

fn parse_cert(pem: &[u8]) -> trc::Result<(CertifiedKey, [DateTime<Utc>; 2])> {
    let mut pems = pem::parse_many(pem).map_err(|err| {
        EventType::Acme(AcmeEvent::Error)
            .reason(err)
            .caused_by(trc::location!())
    })?;
    if pems.len() < 2 {
        return Err(EventType::Acme(AcmeEvent::Error)
            .caused_by(trc::location!())
            .ctx(trc::Key::Size, pems.len())
            .details("Too few PEMs"));
    }
    let pk = match any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        pems.remove(0).contents(),
    ))) {
        Ok(pk) => pk,
        Err(err) => {
            return Err(EventType::Acme(AcmeEvent::Error)
                .reason(err)
                .caused_by(trc::location!()));
        }
    };
    let cert_chain: Vec<CertificateDer> = pems
        .into_iter()
        .map(|p| CertificateDer::from(p.into_contents()))
        .collect();
    let validity = match parse_x509_certificate(&cert_chain[0]) {
        Ok((_, cert)) => {
            let validity = cert.validity();
            [validity.not_before, validity.not_after].map(|t| {
                Utc.timestamp_opt(t.timestamp(), 0)
                    .earliest()
                    .unwrap_or_default()
            })
        }
        Err(err) => {
            return Err(EventType::Acme(AcmeEvent::Error)
                .reason(err)
                .caused_by(trc::location!()));
        }
    };
    let cert = CertifiedKey::new(cert_chain, pk);
    Ok((cert, validity))
}
