/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use registry::schema::enums::{Locale, Permission};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Account {
    pub permissions: Vec<Permission>,
    pub edition: &'static str,
    pub locale: Locale,
}

pub trait AccountApiHandler: Sync + Send {
    fn handle_account_request(
        &self,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl AccountApiHandler for Server {
    async fn handle_account_request(
        &self,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        #[cfg(not(feature = "enterprise"))]
        let edition = "oss";

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let edition = if self.core.is_enterprise_edition() {
            "enterprise"
        } else {
            "community"
        };
        // SPDX-SnippetEnd

        let account_info = self.account_info(access_token.account_id()).await?;

        Ok(JsonResponse::new(Account {
            permissions: access_token.permissions(),
            edition,
            locale: account_info.locale(),
        })
        .into_http_response())
    }
}
