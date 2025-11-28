/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::SpamFilterContext;
use common::{
    Server,
    config::spamfilter::{ReputationCount, ReputationType},
};
use mail_auth::DmarcResult;
use std::future::Future;

pub trait SpamFilterAnalyzeReputation: Sync + Send {
    fn spam_filter_analyze_reputation(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeReputation for Server {
    async fn spam_filter_analyze_reputation(&self, ctx: &mut SpamFilterContext<'_>) {
        // Do not penalize forged domains
        let reputation = self.inner.data.spam_reputation.load();
        if reputation.total.ham > 0
            && reputation.total.spam > 0
            && reputation.total.ham + reputation.total.spam < 100
        {
            if matches!(ctx.input.dmarc_result, Some(DmarcResult::Pass)) {
                // Obtain sender address
                let sender = if !ctx.output.env_from_addr.address.is_empty() {
                    &ctx.output.env_from_addr
                } else {
                    &ctx.output.from.email
                };

                if let Some(count) = reputation.items.get(&ReputationType::Domain(
                    sender.domain_part.sld_or_default().into(),
                )) && let Some(tag) = reputation_tag("REP_DOMAIN", count, &reputation.total)
                {
                    ctx.result.add_tag(tag);
                }
            }

            // Add ASN
            if let Some(asn_id) = &ctx.input.asn {
                ctx.result.add_tag(format!("SOURCE_ASN_{asn_id}"));
                if let Some(count) = reputation.items.get(&ReputationType::Asn(*asn_id))
                    && let Some(tag) = reputation_tag("REP_ASN", count, &reputation.total)
                {
                    ctx.result.add_tag(tag);
                }
            }

            // Add IP
            if let Some(count) = reputation
                .items
                .get(&ReputationType::Ip(ctx.input.remote_ip))
                && let Some(tag) = reputation_tag("REP_IP", count, &reputation.total)
            {
                ctx.result.add_tag(tag);
            }
        } else {
            // Add ASN
            if let Some(asn_id) = &ctx.input.asn {
                ctx.result.add_tag(format!("SOURCE_ASN_{asn_id}"));
            }
        }

        if let Some(country) = &ctx.input.country {
            ctx.result.add_tag(format!("SOURCE_COUNTRY_{country}"));
        }
    }
}

fn reputation_tag(
    prefix: &str,
    token_count: &ReputationCount,
    total_count: &ReputationCount,
) -> Option<String> {
    let total_token_occurrences = token_count.spam + token_count.ham;
    if total_token_occurrences < 10 {
        return None;
    }
    let prob_token_given_spam = token_count.spam as f64 / total_count.spam as f64;
    let prob_token_given_ham = token_count.ham as f64 / total_count.ham as f64;
    if prob_token_given_spam + prob_token_given_ham == 0.0 {
        return None;
    }
    let spam_probability = prob_token_given_spam / (prob_token_given_spam + prob_token_given_ham);
    if spam_probability >= 0.90 {
        Some(format!("{prefix}_VERY_BAD",))
    } else if spam_probability >= 0.75 {
        Some(format!("{prefix}_BAD",))
    } else if spam_probability <= 0.10 {
        Some(format!("{prefix}_VERY_GOOD",))
    } else if spam_probability <= 0.25 {
        Some(format!("{prefix}_GOOD",))
    } else {
        None
    }
}
