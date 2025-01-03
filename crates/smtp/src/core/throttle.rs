/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::smtp::{queue::QueueQuota, *},
    expr::{functions::ResolveVariable, *},
    listener::{limiter::ConcurrencyLimiter, SessionStream},
    ThrottleKey, KV_RATE_LIMIT_HASH,
};
use dashmap::mapref::entry::Entry;
use trc::SmtpEvent;
use utils::config::Rate;

use super::Session;

pub trait NewKey: Sized {
    fn new_key(&self, e: &impl ResolveVariable) -> ThrottleKey;
}

impl NewKey for QueueQuota {
    fn new_key(&self, e: &impl ResolveVariable) -> ThrottleKey {
        let mut hasher = blake3::Hasher::new();

        if (self.keys & THROTTLE_RCPT) != 0 {
            hasher.update(e.resolve_variable(V_RECIPIENT).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_RCPT_DOMAIN) != 0 {
            hasher.update(
                e.resolve_variable(V_RECIPIENT_DOMAIN)
                    .to_string()
                    .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER) != 0 {
            let sender = e.resolve_variable(V_SENDER).into_string();
            hasher.update(
                if !sender.is_empty() {
                    sender.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER_DOMAIN) != 0 {
            let sender_domain = e.resolve_variable(V_SENDER_DOMAIN).into_string();
            hasher.update(
                if !sender_domain.is_empty() {
                    sender_domain.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }

        if let Some(messages) = &self.messages {
            hasher.update(&messages.to_ne_bytes()[..]);
        }

        if let Some(size) = &self.size {
            hasher.update(&size.to_ne_bytes()[..]);
        }

        ThrottleKey {
            hash: hasher.finalize().into(),
        }
    }
}

impl NewKey for Throttle {
    fn new_key(&self, e: &impl ResolveVariable) -> ThrottleKey {
        let mut hasher = blake3::Hasher::new();

        if (self.keys & THROTTLE_RCPT) != 0 {
            hasher.update(e.resolve_variable(V_RECIPIENT).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_RCPT_DOMAIN) != 0 {
            hasher.update(
                e.resolve_variable(V_RECIPIENT_DOMAIN)
                    .to_string()
                    .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER) != 0 {
            let sender = e.resolve_variable(V_SENDER).into_string();
            hasher.update(
                if !sender.is_empty() {
                    sender.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_SENDER_DOMAIN) != 0 {
            let sender_domain = e.resolve_variable(V_SENDER_DOMAIN).into_string();
            hasher.update(
                if !sender_domain.is_empty() {
                    sender_domain.as_ref()
                } else {
                    "<>"
                }
                .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_HELO_DOMAIN) != 0 {
            hasher.update(e.resolve_variable(V_HELO_DOMAIN).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_AUTH_AS) != 0 {
            hasher.update(
                e.resolve_variable(V_AUTHENTICATED_AS)
                    .to_string()
                    .as_bytes(),
            );
        }
        if (self.keys & THROTTLE_LISTENER) != 0 {
            hasher.update(e.resolve_variable(V_LISTENER).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_MX) != 0 {
            hasher.update(e.resolve_variable(V_MX).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_REMOTE_IP) != 0 {
            hasher.update(e.resolve_variable(V_REMOTE_IP).to_string().as_bytes());
        }
        if (self.keys & THROTTLE_LOCAL_IP) != 0 {
            hasher.update(e.resolve_variable(V_LOCAL_IP).to_string().as_bytes());
        }
        if let Some(rate_limit) = &self.rate {
            hasher.update(&rate_limit.period.as_secs().to_ne_bytes()[..]);
            hasher.update(&rate_limit.requests.to_ne_bytes()[..]);
        }
        if let Some(concurrency) = &self.concurrency {
            hasher.update(&concurrency.to_ne_bytes()[..]);
        }

        ThrottleKey {
            hash: hasher.finalize().into(),
        }
    }
}

impl<T: SessionStream> Session<T> {
    pub async fn is_allowed(&mut self) -> bool {
        let throttles = if !self.data.rcpt_to.is_empty() {
            &self.server.core.smtp.session.throttle.rcpt_to
        } else if self.data.mail_from.is_some() {
            &self.server.core.smtp.session.throttle.mail_from
        } else {
            &self.server.core.smtp.session.throttle.connect
        };

        for t in throttles {
            if t.expr.is_empty()
                || self
                    .server
                    .eval_expr(&t.expr, self, "throttle", self.data.session_id)
                    .await
                    .unwrap_or(false)
            {
                if (t.keys & THROTTLE_RCPT_DOMAIN) != 0 {
                    let d = self
                        .data
                        .rcpt_to
                        .last()
                        .map(|r| r.domain.as_str())
                        .unwrap_or_default();

                    if self.data.rcpt_to.iter().filter(|p| p.domain == d).count() > 1 {
                        continue;
                    }
                }

                // Build throttle key
                let key = t.new_key(self);

                // Check concurrency
                if let Some(concurrency) = &t.concurrency {
                    match self
                        .server
                        .inner
                        .data
                        .smtp_session_throttle
                        .entry(key.clone())
                    {
                        Entry::Occupied(mut e) => {
                            let limiter = e.get_mut();
                            if let Some(inflight) = limiter.is_allowed() {
                                self.in_flight.push(inflight);
                            } else {
                                trc::event!(
                                    Smtp(SmtpEvent::ConcurrencyLimitExceeded),
                                    SpanId = self.data.session_id,
                                    Id = t.id.clone(),
                                    Limit = limiter.max_concurrent
                                );
                                return false;
                            }
                        }
                        Entry::Vacant(e) => {
                            let limiter = ConcurrencyLimiter::new(*concurrency);
                            if let Some(inflight) = limiter.is_allowed() {
                                self.in_flight.push(inflight);
                            }
                            e.insert(limiter);
                        }
                    }
                }

                // Check rate
                if let Some(rate) = &t.rate {
                    match self
                        .server
                        .core
                        .storage
                        .lookup
                        .is_rate_allowed(KV_RATE_LIMIT_HASH, key.hash.as_slice(), rate, false)
                        .await
                    {
                        Ok(Some(_)) => {
                            trc::event!(
                                Smtp(SmtpEvent::RateLimitExceeded),
                                SpanId = self.data.session_id,
                                Id = t.id.clone(),
                                Limit = vec![
                                    trc::Value::from(rate.requests),
                                    trc::Value::from(rate.period)
                                ],
                            );

                            return false;
                        }
                        Err(err) => {
                            trc::error!(err
                                .span_id(self.data.session_id)
                                .caused_by(trc::location!()));
                        }
                        _ => (),
                    }
                }
            }
        }

        true
    }

    pub async fn throttle_rcpt(&self, rcpt: &str, rate: &Rate, ctx: &str) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(rcpt.as_bytes());
        hasher.update(ctx.as_bytes());
        hasher.update(&rate.period.as_secs().to_ne_bytes()[..]);
        hasher.update(&rate.requests.to_ne_bytes()[..]);

        match self
            .server
            .core
            .storage
            .lookup
            .is_rate_allowed(
                KV_RATE_LIMIT_HASH,
                hasher.finalize().as_bytes(),
                rate,
                false,
            )
            .await
        {
            Ok(None) => true,
            Ok(Some(_)) => false,
            Err(err) => {
                trc::error!(err
                    .span_id(self.data.session_id)
                    .caused_by(trc::location!()));
                true
            }
        }
    }
}
