/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    hash::Hash,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use common::{
    Inner, Server,
    auth::AccessToken,
    config::smtp::auth::VerifyStrategy,
    listener::{ServerInstance, asn::AsnGeoLookupResult},
};

use directory::Directory;
use mail_auth::{IprevOutput, SpfOutput};
use smtp_proto::request::receiver::{
    BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver, RequestReceiver,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    inbound::auth::SaslToken,
    queue::{DomainPart, QueueId},
};

pub mod params;
pub mod throttle;

#[derive(Clone)]
pub struct SmtpSessionManager {
    pub inner: Arc<Inner>,
}

impl SmtpSessionManager {
    pub fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }
}

pub enum State {
    Request(RequestReceiver),
    Bdat(BdatReceiver),
    Data(DataReceiver),
    Sasl(LineReceiver<SaslToken>),
    DataTooLarge(DummyDataReceiver),
    RequestTooLarge(DummyLineReceiver),
    Accepted(QueueId),
    None,
}

pub struct Session<T: AsyncWrite + AsyncRead> {
    pub hostname: String,
    pub state: State,
    pub instance: Arc<ServerInstance>,
    pub server: Server,
    pub stream: T,
    pub data: SessionData,
    pub params: SessionParameters,
}

pub struct SessionData {
    pub session_id: u64,
    pub local_ip: IpAddr,
    pub local_ip_str: String,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_ip_str: String,
    pub remote_port: u16,
    pub asn_geo_data: AsnGeoLookupResult,
    pub helo_domain: String,

    pub mail_from: Option<SessionAddress>,
    pub rcpt_to: Vec<SessionAddress>,
    pub rcpt_errors: usize,
    pub rcpt_oks: usize,
    pub message: Vec<u8>,

    pub authenticated_as: Option<Arc<AccessToken>>,
    pub auth_errors: usize,

    pub priority: i16,
    pub delivery_by: i64,
    pub future_release: u64,

    pub valid_until: Instant,
    pub bytes_left: usize,
    pub messages_sent: usize,

    pub iprev: Option<IprevOutput>,
    pub spf_ehlo: Option<SpfOutput>,
    pub spf_mail_from: Option<SpfOutput>,
    pub dnsbl_error: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct SessionAddress {
    pub address: String,
    pub address_lcase: String,
    pub domain: String,
    pub flags: u64,
    pub dsn_info: Option<String>,
}

#[derive(Debug, Default)]
pub struct SessionParameters {
    // Global parameters
    pub timeout: Duration,

    // Ehlo parameters
    pub ehlo_require: bool,
    pub ehlo_reject_non_fqdn: bool,

    // Auth parameters
    pub auth_directory: Option<Arc<Directory>>,
    pub auth_require: bool,
    pub auth_errors_max: usize,
    pub auth_errors_wait: Duration,

    // Rcpt parameters
    pub rcpt_errors_max: usize,
    pub rcpt_errors_wait: Duration,
    pub rcpt_max: usize,
    pub rcpt_dsn: bool,
    pub can_expn: bool,
    pub can_vrfy: bool,
    pub max_message_size: usize,

    // Mail authentication parameters
    pub iprev: VerifyStrategy,
    pub spf_ehlo: VerifyStrategy,
    pub spf_mail_from: VerifyStrategy,
}

impl SessionData {
    pub fn new(
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        asn_geo_data: AsnGeoLookupResult,
        session_id: u64,
    ) -> Self {
        SessionData {
            session_id,
            local_ip,
            local_port,
            remote_ip,
            local_ip_str: local_ip.to_string(),
            remote_ip_str: remote_ip.to_string(),
            remote_port,
            asn_geo_data,
            helo_domain: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            authenticated_as: None,
            priority: 0,
            valid_until: Instant::now(),
            rcpt_errors: 0,
            rcpt_oks: 0,
            message: Vec::with_capacity(0),
            auth_errors: 0,
            messages_sent: 0,
            bytes_left: 0,
            delivery_by: 0,
            future_release: 0,
            iprev: None,
            spf_ehlo: None,
            spf_mail_from: None,
            dnsbl_error: None,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::Request(RequestReceiver::default())
    }
}

impl PartialEq for SessionAddress {
    fn eq(&self, other: &Self) -> bool {
        self.address_lcase == other.address_lcase
    }
}

impl Eq for SessionAddress {}

impl Hash for SessionAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address_lcase.hash(state);
    }
}

impl Ord for SessionAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.domain.cmp(&other.domain) {
            std::cmp::Ordering::Equal => self.address_lcase.cmp(&other.address_lcase),
            order => order,
        }
    }
}

impl PartialOrd for SessionAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Session<common::listener::stream::NullIo> {
    pub fn local(
        server: Server,
        instance: std::sync::Arc<ServerInstance>,
        data: SessionData,
    ) -> Self {
        Session {
            hostname: "localhost".into(),
            state: State::None,
            instance,
            server,
            stream: common::listener::stream::NullIo::default(),
            data,
            params: SessionParameters {
                timeout: Default::default(),
                ehlo_require: Default::default(),
                ehlo_reject_non_fqdn: Default::default(),
                auth_directory: Default::default(),
                auth_require: Default::default(),
                auth_errors_max: Default::default(),
                auth_errors_wait: Default::default(),
                rcpt_errors_max: Default::default(),
                rcpt_errors_wait: Default::default(),
                rcpt_max: Default::default(),
                rcpt_dsn: Default::default(),
                max_message_size: Default::default(),
                iprev: VerifyStrategy::Disable,
                spf_ehlo: VerifyStrategy::Disable,
                spf_mail_from: VerifyStrategy::Disable,
                can_expn: false,
                can_vrfy: false,
            },
        }
    }

    pub fn has_failed(&mut self) -> Option<String> {
        if self.stream.tx_buf.first().is_none_or(|&c| c == b'2') {
            self.stream.tx_buf.clear();
            None
        } else {
            let response = std::str::from_utf8(&self.stream.tx_buf)
                .unwrap()
                .trim()
                .into();
            self.stream.tx_buf.clear();
            Some(response)
        }
    }
}

impl SessionData {
    pub fn local(
        authenticated_as: Arc<AccessToken>,
        mail_from: Option<SessionAddress>,
        rcpt_to: Vec<SessionAddress>,
        message: Vec<u8>,
        session_id: u64,
    ) -> Self {
        SessionData {
            local_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            remote_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            local_ip_str: "127.0.0.1".into(),
            remote_ip_str: "127.0.0.1".into(),
            remote_port: 0,
            local_port: 0,
            session_id,
            asn_geo_data: AsnGeoLookupResult::default(),
            helo_domain: "localhost".into(),
            mail_from,
            rcpt_to,
            rcpt_errors: 0,
            rcpt_oks: 0,
            message,
            authenticated_as: Some(authenticated_as),
            auth_errors: 0,
            priority: 0,
            delivery_by: 0,
            future_release: 0,
            valid_until: Instant::now(),
            bytes_left: 0,
            messages_sent: 0,
            iprev: None,
            spf_ehlo: None,
            spf_mail_from: None,
            dnsbl_error: None,
        }
    }
}

impl Default for SessionData {
    fn default() -> Self {
        Self::local(Arc::new(AccessToken::from_id(0)), None, vec![], vec![], 0)
    }
}

impl SessionAddress {
    pub fn new(address: String) -> Self {
        let address_lcase = address.to_lowercase();
        SessionAddress {
            domain: address_lcase.domain_part().into(),
            address_lcase,
            address,
            flags: 0,
            dsn_info: None,
        }
    }
}
