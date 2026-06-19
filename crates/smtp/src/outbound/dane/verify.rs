/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::resolver::{Tlsa, TlsaEntry, TlsaMatching};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256, Sha512};
use trc::DaneEvent;
use x509_parser::prelude::{FromDer, GeneralName, SubjectPublicKeyInfo, X509Certificate};

use crate::queue::{Error, ErrorDetails, HostResponse, Status};

pub trait TlsaVerify {
    fn verify(
        &self,
        session_id: u64,
        hostname: &str,
        reference_ids: &[&str],
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<HostResponse<Box<str>>, ErrorDetails>>;
}

struct ChainCert<'a> {
    raw: &'a [u8],
    cert: X509Certificate<'a>,
}

impl TlsaVerify for Tlsa {
    fn verify(
        &self,
        session_id: u64,
        hostname: &str,
        reference_ids: &[&str],
        certificates: Option<&[CertificateDer<'_>]>,
    ) -> Result<(), Status<HostResponse<Box<str>>, ErrorDetails>> {
        let certificates = match certificates {
            Some(certificates) if !certificates.is_empty() => certificates,
            _ => {
                trc::event!(
                    Dane(DaneEvent::NoCertificatesFound),
                    SpanId = session_id,
                    Hostname = hostname.to_string(),
                );

                return Err(Status::TemporaryFailure(ErrorDetails {
                    entity: hostname.into(),
                    details: Error::DaneError("No certificates were provided by host".into()),
                }));
            }
        };

        let mut chain = Vec::with_capacity(certificates.len());
        for der_certificate in certificates {
            match X509Certificate::from_der(der_certificate.as_ref()) {
                Ok((_, cert)) => chain.push(ChainCert {
                    raw: der_certificate.as_ref(),
                    cert,
                }),
                Err(err) => {
                    trc::event!(
                        Dane(DaneEvent::CertificateParseError),
                        SpanId = session_id,
                        Hostname = hostname.to_string(),
                        Reason = err.to_string(),
                    );

                    return Err(Status::TemporaryFailure(ErrorDetails {
                        entity: hostname.into(),
                        details: Error::DaneError("Failed to parse X.509 certificate".into()),
                    }));
                }
            }
        }

        if verify_end_entity(self, session_id, hostname, &chain)
            || verify_trust_anchor(self, session_id, hostname, reference_ids, &chain)
        {
            trc::event!(
                Dane(DaneEvent::AuthenticationSuccess),
                SpanId = session_id,
                Hostname = hostname.to_string(),
            );

            Ok(())
        } else {
            trc::event!(
                Dane(DaneEvent::AuthenticationFailure),
                SpanId = session_id,
                Hostname = hostname.to_string(),
            );

            Err(Status::PermanentFailure(ErrorDetails {
                entity: hostname.into(),
                details: Error::DaneError("No matching certificates found in TLSA records".into()),
            }))
        }
    }
}

fn verify_end_entity(
    tlsa: &Tlsa,
    session_id: u64,
    hostname: &str,
    chain: &[ChainCert<'_>],
) -> bool {
    if !tlsa.has_end_entities {
        return false;
    }
    let leaf = &chain[0];
    for record in tlsa.entries.iter().filter(|record| record.is_end_entity) {
        if record_matches(record, &leaf.cert, leaf.raw) {
            trc::event!(
                Dane(DaneEvent::TlsaRecordMatch),
                SpanId = session_id,
                Hostname = hostname.to_string(),
                Type = "end-entity",
            );
            return true;
        }
    }
    false
}

fn verify_trust_anchor(
    tlsa: &Tlsa,
    session_id: u64,
    hostname: &str,
    reference_ids: &[&str],
    chain: &[ChainCert<'_>],
) -> bool {
    if !tlsa.has_intermediates {
        return false;
    }

    let path = build_verified_chain(chain);
    let leaf = &chain[path[0]];

    for depth in 0..path.len() {
        let anchor = &chain[path[depth]];

        for record in tlsa.entries.iter().filter(|record| !record.is_end_entity) {
            if record_matches(record, &anchor.cert, anchor.raw)
                && dates_valid(chain, &path[..depth])
                && name_matches(&leaf.cert, reference_ids)
            {
                trc::event!(
                    Dane(DaneEvent::TlsaRecordMatch),
                    SpanId = session_id,
                    Hostname = hostname.to_string(),
                    Type = "trust-anchor",
                );
                return true;
            }
        }

        for record in tlsa.entries.iter().filter(|record| {
            !record.is_end_entity && record.is_spki && record.matching == TlsaMatching::Full
        }) {
            if let Ok((_, spki)) = SubjectPublicKeyInfo::from_der(&record.data)
                && anchor.cert.verify_signature(Some(&spki)).is_ok()
                && dates_valid(chain, &path[..=depth])
                && name_matches(&leaf.cert, reference_ids)
            {
                trc::event!(
                    Dane(DaneEvent::TlsaRecordMatch),
                    SpanId = session_id,
                    Hostname = hostname.to_string(),
                    Type = "trust-anchor-bare-key",
                );
                return true;
            }
        }
    }

    false
}

fn build_verified_chain(chain: &[ChainCert<'_>]) -> Vec<usize> {
    let mut path = vec![0];
    let mut used = vec![false; chain.len()];
    used[0] = true;

    loop {
        let current = &chain[*path.last().unwrap()].cert;
        if current.verify_signature(None).is_ok() {
            break;
        }
        let issuer = (0..chain.len()).find(|&idx| {
            !used[idx]
                && current
                    .verify_signature(Some(chain[idx].cert.public_key()))
                    .is_ok()
        });
        match issuer {
            Some(idx) => {
                used[idx] = true;
                path.push(idx);
            }
            None => break,
        }
    }

    path
}

fn dates_valid(chain: &[ChainCert<'_>], path: &[usize]) -> bool {
    path.iter()
        .all(|&idx| chain[idx].cert.validity().is_valid())
}

fn record_matches(record: &TlsaEntry, cert: &X509Certificate<'_>, raw: &[u8]) -> bool {
    let selected: &[u8] = if record.is_spki {
        cert.public_key().raw
    } else {
        raw
    };

    match record.matching {
        TlsaMatching::Full => selected == record.data.as_slice(),
        TlsaMatching::Sha256 => Sha256::digest(selected).as_slice() == record.data.as_slice(),
        TlsaMatching::Sha512 => Sha512::digest(selected).as_slice() == record.data.as_slice(),
    }
}

fn name_matches(cert: &X509Certificate<'_>, reference_ids: &[&str]) -> bool {
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let mut has_dns_id = false;
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns_id) = name {
                has_dns_id = true;
                if reference_ids
                    .iter()
                    .any(|reference| dns_id_matches(dns_id, reference))
                {
                    return true;
                }
            }
        }
        if has_dns_id {
            return false;
        }
    }

    cert.subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .any(|cn| {
            reference_ids
                .iter()
                .any(|reference| dns_id_matches(cn, reference))
        })
}

fn dns_id_matches(presented: &str, reference: &str) -> bool {
    let presented = presented.trim_end_matches('.');
    let reference = reference.trim_end_matches('.');

    if let Some(suffix) = presented.strip_prefix("*.") {
        match reference.split_once('.') {
            Some((label, rest)) => !label.is_empty() && rest.eq_ignore_ascii_case(suffix),
            None => false,
        }
    } else {
        presented.eq_ignore_ascii_case(reference)
    }
}
