/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Server;
use ahash::{AHashMap, AHashSet};
use dns_update::{
    Algorithm, DnsUpdater, TsigAlgorithm,
    dnssec::{
        self, SigningKey,
        crypto::{EcdsaSigningKey, Ed25519SigningKey},
    },
    providers::{ovh::OvhEndpoint, rfc2136::DnsAddress},
};
use rcgen::generate_simple_self_signed;
use registry::schema::{
    enums,
    prelude::Object,
    structs::{Certificate, DnsServer, SystemSettings},
};
use rustls::{
    SupportedProtocolVersion,
    crypto::ring::sign::any_supported_type,
    sign::CertifiedKey,
    version::{TLS12, TLS13},
};
use rustls_pemfile::{Item, certs, read_all};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{io::Cursor, net::SocketAddr, sync::Arc};
use store::{
    registry::{bootstrap::Bootstrap, write::RegistryWrite},
    write::now,
};
use trc::AddContext;

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

impl Server {
    pub async fn build_dns_updater(&self, id: u64) -> trc::Result<DnsUpdater> {
        let Some(server) = self
            .registry()
            .object::<DnsServer>(id.into())
            .await
            .caused_by(trc::location!())?
        else {
            trc::bail!(
                trc::DnsEvent::BuildError
                    .into_err()
                    .id(id.to_string())
                    .details("DNS server settings not found")
            );
        };

        match server {
            DnsServer::Tsig(server) => DnsUpdater::new_rfc2136_tsig(
                match server.protocol {
                    enums::IpProtocol::Udp => DnsAddress::Tcp(SocketAddr::new(
                        server.host.into_inner(),
                        server.port as u16,
                    )),
                    enums::IpProtocol::Tcp => DnsAddress::Udp(SocketAddr::new(
                        server.host.into_inner(),
                        server.port as u16,
                    )),
                },
                server.key_name,
                server
                    .key
                    .secret()
                    .await
                    .map_err(|err| {
                        trc::DnsEvent::BuildError
                            .reason(err)
                            .details("Failed to obtain TSIG key secret")
                            .id(id.to_string())
                    })?
                    .into_owned()
                    .into_bytes(),
                match server.tsig_algorithm {
                    enums::TsigAlgorithm::HmacMd5 => TsigAlgorithm::HmacMd5,
                    enums::TsigAlgorithm::Gss => TsigAlgorithm::Gss,
                    enums::TsigAlgorithm::HmacSha1 => TsigAlgorithm::HmacSha1,
                    enums::TsigAlgorithm::HmacSha224 => TsigAlgorithm::HmacSha224,
                    enums::TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
                    enums::TsigAlgorithm::HmacSha256128 => TsigAlgorithm::HmacSha256_128,
                    enums::TsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
                    enums::TsigAlgorithm::HmacSha384192 => TsigAlgorithm::HmacSha384_192,
                    enums::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
                    enums::TsigAlgorithm::HmacSha512256 => TsigAlgorithm::HmacSha512_256,
                },
            ),
            DnsServer::Sig0(server) => {
                let key_bytes = server.key.secret().await.map_err(|err| {
                    trc::DnsEvent::BuildError
                        .reason(err)
                        .details("Failed to obtain key secret")
                        .id(id.to_string())
                })?;

                let pem_parsed = pem::parse(key_bytes.as_bytes()).map_err(|err| {
                    trc::DnsEvent::BuildError
                        .reason(err)
                        .details("Failed to parse PEM key")
                        .id(id.to_string())
                })?;
                let pkcs8_der = PrivatePkcs8KeyDer::from(pem_parsed.contents());

                let signing_key: Box<dyn SigningKey> = match server.sig0_algorithm {
                    enums::Sig0Algorithm::EcdsaP256Sha256 => Box::new(
                        EcdsaSigningKey::from_pkcs8(&pkcs8_der, dnssec::Algorithm::ECDSAP256SHA256)
                            .map_err(|err| {
                                trc::DnsEvent::BuildError
                                    .reason(err)
                                    .details("Failed to build ECDSA P-256 signing key")
                                    .id(id.to_string())
                            })?,
                    ),
                    enums::Sig0Algorithm::EcdsaP384Sha384 => Box::new(
                        EcdsaSigningKey::from_pkcs8(&pkcs8_der, dnssec::Algorithm::ECDSAP384SHA384)
                            .map_err(|err| {
                                trc::DnsEvent::BuildError
                                    .reason(err)
                                    .details("Failed to build ECDSA P-384 signing key")
                                    .id(id.to_string())
                            })?,
                    ),
                    enums::Sig0Algorithm::Ed25519 => {
                        Box::new(Ed25519SigningKey::from_pkcs8(&pkcs8_der).map_err(|err| {
                            trc::DnsEvent::BuildError
                                .reason(err)
                                .details("Failed to build Ed25519 signing key")
                                .id(id.to_string())
                        })?)
                    }
                };

                DnsUpdater::new_rfc2136_sig0(
                    match server.protocol {
                        enums::IpProtocol::Udp => DnsAddress::Tcp(SocketAddr::new(
                            server.host.into_inner(),
                            server.port as u16,
                        )),
                        enums::IpProtocol::Tcp => DnsAddress::Udp(SocketAddr::new(
                            server.host.into_inner(),
                            server.port as u16,
                        )),
                    },
                    server.signer_name,
                    signing_key,
                    server.public_key,
                    match server.sig0_algorithm {
                        enums::Sig0Algorithm::EcdsaP256Sha256 => Algorithm::ECDSAP256SHA256,
                        enums::Sig0Algorithm::EcdsaP384Sha384 => Algorithm::ECDSAP384SHA384,
                        enums::Sig0Algorithm::Ed25519 => Algorithm::ED25519,
                    },
                )
            }
            DnsServer::Cloudflare(server) => DnsUpdater::new_cloudflare(
                server.secret.secret().await.map_err(|err| {
                    trc::DnsEvent::BuildError
                        .reason(err)
                        .details("Failed to obtain key secret")
                        .id(id.to_string())
                })?,
                server.email,
                server.timeout.into_inner().into(),
            ),
            DnsServer::DigitalOcean(server) => DnsUpdater::new_digitalocean(
                server.secret.secret().await.map_err(|err| {
                    trc::DnsEvent::BuildError
                        .reason(err)
                        .details("Failed to obtain key secret")
                        .id(id.to_string())
                })?,
                server.timeout.into_inner().into(),
            ),
            DnsServer::DeSEC(server) => DnsUpdater::new_desec(
                server.secret.secret().await.map_err(|err| {
                    trc::DnsEvent::BuildError
                        .reason(err)
                        .details("Failed to obtain key secret")
                        .id(id.to_string())
                })?,
                server.timeout.into_inner().into(),
            ),
            DnsServer::Ovh(server) => DnsUpdater::new_ovh(
                server.application_key,
                server.application_secret.secret().await.map_err(|err| {
                    trc::DnsEvent::BuildError
                        .reason(err)
                        .details("Failed to obtain application secret")
                        .id(id.to_string())
                })?,
                server.consumer_key.secret().await.map_err(|err| {
                    trc::DnsEvent::BuildError
                        .reason(err)
                        .details("Failed to obtain consumer key")
                        .id(id.to_string())
                })?,
                match server.ovh_endpoint {
                    enums::OvhEndpoint::OvhEu => OvhEndpoint::OvhEu,
                    enums::OvhEndpoint::OvhCa => OvhEndpoint::OvhCa,
                    enums::OvhEndpoint::KimsufiEu => OvhEndpoint::KimsufiEu,
                    enums::OvhEndpoint::KimsufiCa => OvhEndpoint::KimsufiCa,
                    enums::OvhEndpoint::SoyoustartEu => OvhEndpoint::SoyoustartEu,
                    enums::OvhEndpoint::SoyoustartCa => OvhEndpoint::SoyoustartCa,
                },
                server.timeout.into_inner().into(),
            ),
        }
        .map_err(|err| {
            trc::DnsEvent::BuildError
                .reason(err)
                .details("Failed to build DNS updater")
                .id(id.to_string())
        })
    }
}

pub(crate) async fn parse_certificates(
    bp: &mut Bootstrap,
    certificates: &mut AHashMap<Box<str>, Arc<CertifiedKey>>,
    subject_names: &mut AHashSet<Box<str>>,
) {
    let system = bp.setting_infallible::<SystemSettings>().await;

    // Parse certificates
    let now = now() as i64;
    let mut certs_expired = Vec::new();
    let mut certs_expirations = AHashMap::new();
    for cert_obj in bp.list_infallible::<Certificate>().await {
        let not_valid_after = cert_obj.object.not_valid_after.timestamp();
        let not_valid_before = cert_obj.object.not_valid_before.timestamp();

        if not_valid_after <= now {
            certs_expired.push((
                cert_obj.id,
                cert_obj
                    .object
                    .subject_alternative_names
                    .clone()
                    .into_inner(),
                Object {
                    inner: cert_obj.object.into(),
                    revision: cert_obj.revision,
                },
            ));
            continue;
        } else if not_valid_before > now {
            continue; // Skip certificates that are not yet valid
        }

        let mut cert = cert_obj.object;
        let secret = match cert.private_key.secret().await {
            Ok(secret) => secret.into_owned().into_bytes(),
            Err(err) => {
                bp.build_error(
                    cert_obj.id,
                    format!("Failed to obtain private key secret: {err}"),
                );
                continue;
            }
        };
        let public = match cert.certificate.value().await {
            Ok(value) => value.into_owned().into_bytes(),
            Err(err) => {
                bp.build_error(
                    cert_obj.id,
                    format!("Failed to obtain certificate value: {err}"),
                );
                continue;
            }
        };

        // Add default certificate
        if system
            .default_certificate_id
            .as_ref()
            .is_some_and(|id| *id == cert_obj.id.id())
        {
            cert.subject_alternative_names
                .push_unchecked("*".to_string());
        }

        // Ensure that the most up-to-date certificate is used
        cert.subject_alternative_names.inner_mut().retain(|name| {
            if certs_expirations
                .get(name)
                .is_none_or(|expires| *expires < not_valid_after)
            {
                certs_expirations.insert(name.clone(), not_valid_after);
                true
            } else {
                false
            }
        });

        match build_certified_key(public, secret) {
            Ok(key) => {
                // Add certificates
                let key = Arc::new(key);
                for name in cert.subject_alternative_names.into_inner() {
                    subject_names.insert(name.as_str().into());
                    certificates.insert(
                        name.strip_prefix("*.")
                            .map(Into::into)
                            .unwrap_or_else(|| name.into_boxed_str()),
                        key.clone(),
                    );
                }
            }
            Err(err) => {
                bp.build_error(cert_obj.id, format!("Invalid certificate: {err}"));
            }
        }
    }

    // Remove expired certificates
    if !certs_expired.is_empty() {
        for (id, sans, object) in certs_expired {
            if let Err(err) = bp
                .registry
                .write(RegistryWrite::delete_object(id, &object))
                .await
            {
                trc::error!(
                    err.details("Failed to delete expired TLS certificate from registry.")
                        .caused_by(trc::location!())
                );
            } else {
                trc::event!(
                    Tls(trc::TlsEvent::ExpiredCertificateRemoved),
                    Details = sans
                );
            }
        }
    }
}

pub(crate) fn build_certified_key(
    cert: Vec<u8>,
    pk_bytes: Vec<u8>,
) -> Result<CertifiedKey, String> {
    let mut pk = None;
    for item in read_all(&mut Cursor::new(pk_bytes)) {
        match item.map_err(|err| format!("Failed to read private key PEM: {err}"))? {
            Item::Pkcs8Key(key) => {
                pk = Some(PrivateKeyDer::Pkcs8(key));
                break;
            }
            Item::Pkcs1Key(key) => {
                pk = Some(PrivateKeyDer::Pkcs1(key));
                break;
            }
            Item::Sec1Key(key) => {
                pk = Some(PrivateKeyDer::Sec1(key));
                break;
            }
            _ => continue, // Skip certificates, DH params, etc.
        }
    }
    let pk = pk.ok_or_else(|| "No private keys found.".to_string())?;
    let cert = certs(&mut Cursor::new(cert))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("Failed to read certificates: {err}"))?;

    if !cert.is_empty() {
        Ok(CertifiedKey {
            cert,
            key: any_supported_type(&pk)
                .map_err(|err| format!("Failed to sign certificate: {err}",))?,
            ocsp: None,
        })
    } else {
        Err("No certificates found.".to_string())
    }
}

pub(crate) fn build_self_signed_cert(
    domains: impl Into<Vec<String>>,
) -> Result<CertifiedKey, String> {
    let cert = generate_simple_self_signed(domains)
        .map_err(|err| format!("Failed to generate self-signed certificate: {err}",))?;
    build_certified_key(
        cert.serialize_pem().unwrap().into_bytes(),
        cert.serialize_private_key_pem().into_bytes(),
    )
}
