/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use mail_auth::{report::AuthFailureType, AuthenticationResults, SpfOutput};
use utils::config::Rate;

use crate::core::Session;

impl<T: SessionStream> Session<T> {
    pub async fn send_spf_report(
        &self,
        rcpt: &str,
        rate: &Rate,
        rejected: bool,
        output: &SpfOutput,
    ) {
        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "spf").await {
            tracing::debug!(
                parent: &self.span,
                context = "report",
                report = "spf",
                event = "throttle",
                rcpt = rcpt,
            );
            return;
        }

        // Generate report
        let config = &self.core.core.smtp.report.spf;
        let from_addr = self
            .core
            .core
            .eval_if(&config.address, self)
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
        let mut report = Vec::with_capacity(128);
        self.new_auth_failure(AuthFailureType::Spf, rejected)
            .with_authentication_results(
                if let Some(mail_from) = &self.data.mail_from {
                    AuthenticationResults::new(&self.hostname).with_spf_mailfrom_result(
                        output,
                        self.data.remote_ip,
                        &mail_from.address,
                        &self.data.helo_domain,
                    )
                } else {
                    AuthenticationResults::new(&self.hostname).with_spf_ehlo_result(
                        output,
                        self.data.remote_ip,
                        &self.data.helo_domain,
                    )
                }
                .to_string(),
            )
            .with_spf_dns(format!("txt : {} : v=SPF1", output.domain())) // TODO use DNS record
            .write_rfc5322(
                (
                    self.core
                        .core
                        .eval_if(&config.name, self)
                        .await
                        .unwrap_or_else(|| "Mailer Daemon".to_string())
                        .as_str(),
                    from_addr.as_str(),
                ),
                rcpt,
                &self
                    .core
                    .core
                    .eval_if(&config.subject, self)
                    .await
                    .unwrap_or_else(|| "SPF Report".to_string()),
                &mut report,
            )
            .ok();

        tracing::info!(
            parent: &self.span,
            context = "report",
            report = "spf",
            event = "queue",
            rcpt = rcpt,
            "Queueing SPF authentication failure report."
        );

        // Send report
        self.core
            .send_report(
                &from_addr,
                [rcpt].into_iter(),
                report,
                &config.sign,
                &self.span,
                true,
            )
            .await;
    }
}
