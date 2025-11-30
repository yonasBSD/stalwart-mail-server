/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;

use crate::SpamFilterContext;

pub trait SpamClassifier {
    fn spam_classify(
        &self,
        ctx: &SpamFilterContext<'_>,
    ) -> impl Future<Output = trc::Result<Option<f64>>> + Send;

    fn spam_train(
        &self,
        ctx: &SpamFilterContext<'_>,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl SpamClassifier for Server {
    async fn spam_train(&self, ctx: &SpamFilterContext<'_>) -> trc::Result<()> {
        todo!()
    }

    async fn spam_classify(&self, ctx: &SpamFilterContext<'_>) -> trc::Result<Option<f64>> {
        todo!()
    }
}
