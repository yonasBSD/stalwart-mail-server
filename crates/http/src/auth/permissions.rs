/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use registry::schema::enums::Permission;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Permissions {
    pub permissions: Vec<Permission>,
    #[serde(rename = "isEnterprise")]
    pub is_enterprise: bool,
}

pub trait PermissionsApiHandler: Sync + Send {
    fn handle_permissions_request(
        &self,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl PermissionsApiHandler for Server {
    async fn handle_permissions_request(
        &self,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        #[cfg(not(feature = "enterprise"))]
        let is_enterprise = false;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let is_enterprise = self.core.is_enterprise_edition();
        // SPDX-SnippetEnd

        Ok(JsonResponse::new(Permissions {
            permissions: access_token.permissions(),
            is_enterprise,
        })
        .into_http_response())
    }
}
