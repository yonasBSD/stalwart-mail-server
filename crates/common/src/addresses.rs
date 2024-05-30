/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::borrow::Cow;

use directory::Directory;
use utils::config::{utils::AsKey, Config};

use crate::{
    config::smtp::session::AddressMapping,
    expr::{
        functions::ResolveVariable, if_block::IfBlock, tokenizer::TokenMap, Variable, V_RECIPIENT,
    },
    Core,
};

impl Core {
    pub async fn email_to_ids(
        &self,
        directory: &Directory,
        email: &str,
    ) -> directory::Result<Vec<u32>> {
        let mut address = self
            .smtp
            .session
            .rcpt
            .subaddressing
            .to_subaddress(self, email)
            .await;

        for _ in 0..2 {
            let result = directory.email_to_ids(address.as_ref()).await?;

            if !result.is_empty() {
                return Ok(result);
            } else if let Some(catch_all) = self
                .smtp
                .session
                .rcpt
                .catch_all
                .to_catch_all(self, email)
                .await
            {
                address = catch_all;
            } else {
                break;
            }
        }

        Ok(vec![])
    }

    pub async fn rcpt(&self, directory: &Directory, email: &str) -> directory::Result<bool> {
        // Expand subaddress
        let mut address = self
            .smtp
            .session
            .rcpt
            .subaddressing
            .to_subaddress(self, email)
            .await;

        for _ in 0..2 {
            if directory.rcpt(address.as_ref()).await? {
                return Ok(true);
            } else if let Some(catch_all) = self
                .smtp
                .session
                .rcpt
                .catch_all
                .to_catch_all(self, email)
                .await
            {
                address = catch_all;
            } else {
                break;
            }
        }

        Ok(false)
    }

    pub async fn vrfy(
        &self,
        directory: &Directory,
        address: &str,
    ) -> directory::Result<Vec<String>> {
        directory
            .vrfy(
                self.smtp
                    .session
                    .rcpt
                    .subaddressing
                    .to_subaddress(self, address)
                    .await
                    .as_ref(),
            )
            .await
    }

    pub async fn expn(
        &self,
        directory: &Directory,
        address: &str,
    ) -> directory::Result<Vec<String>> {
        directory
            .expn(
                self.smtp
                    .session
                    .rcpt
                    .subaddressing
                    .to_subaddress(self, address)
                    .await
                    .as_ref(),
            )
            .await
    }
}

impl AddressMapping {
    pub fn parse(config: &mut Config, key: impl AsKey) -> Self {
        let key = key.as_key();
        if let Some(value) = config.value(key.as_str()) {
            match value {
                "true" => AddressMapping::Enable,
                "false" => AddressMapping::Disable,
                _ => {
                    config.new_parse_error(
                        key,
                        format!("Invalid value for address mapping {value:?}",),
                    );
                    AddressMapping::Disable
                }
            }
        } else if let Some(if_block) = IfBlock::try_parse(
            config,
            key,
            &TokenMap::default().with_variables_map([
                ("address", V_RECIPIENT),
                ("email", V_RECIPIENT),
                ("rcpt", V_RECIPIENT),
            ]),
        ) {
            AddressMapping::Custom(if_block)
        } else {
            AddressMapping::Enable
        }
    }
}

struct Address<'x>(&'x str);

impl ResolveVariable for Address<'_> {
    fn resolve_variable(&self, _: u32) -> crate::expr::Variable {
        Variable::from(self.0)
    }
}

impl AddressMapping {
    pub async fn to_subaddress<'x, 'y: 'x>(
        &'x self,
        core: &Core,
        address: &'y str,
    ) -> Cow<'x, str> {
        match self {
            AddressMapping::Enable => {
                if let Some((local_part, domain_part)) = address.rsplit_once('@') {
                    if let Some((local_part, _)) = local_part.split_once('+') {
                        return format!("{}@{}", local_part, domain_part).into();
                    }
                }
            }
            AddressMapping::Custom(if_block) => {
                if let Ok(result) = String::try_from(
                    if_block
                        .eval(&Address(address), core, "session.rcpt.sub-addressing")
                        .await,
                ) {
                    return result.into();
                }
            }
            AddressMapping::Disable => (),
        }

        address.into()
    }

    pub async fn to_catch_all<'x, 'y: 'x>(
        &'x self,
        core: &Core,
        address: &'y str,
    ) -> Option<Cow<'x, str>> {
        match self {
            AddressMapping::Enable => address
                .rsplit_once('@')
                .map(|(_, domain_part)| format!("@{}", domain_part))
                .map(Cow::Owned),

            AddressMapping::Custom(if_block) => {
                if let Ok(result) = String::try_from(
                    if_block
                        .eval(&Address(address), core, "session.rcpt.catch-all")
                        .await,
                ) {
                    Some(result.into())
                } else {
                    None
                }
            }
            AddressMapping::Disable => None,
        }
    }
}
