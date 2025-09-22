/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::parser::{JsonObjectParser, json::Parser};
use types::type_state::DataType;

impl JsonObjectParser for DataType {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut hash = 0;
        let mut shift = 0;

        while let Some(ch) = parser.next_unescaped()? {
            if shift < 128 {
                hash |= (ch as u128) << shift;
                shift += 8;
            } else {
                return Err(parser.error_value());
            }
        }

        match hash {
            0x006c_6961_6d45 => Ok(DataType::Email),
            0x0079_7265_7669_6c65_446c_6961_6d45 => Ok(DataType::EmailDelivery),
            0x006e_6f69_7373_696d_6275_536c_6961_6d45 => Ok(DataType::EmailSubmission),
            0x0078_6f62_6c69_614d => Ok(DataType::Mailbox),
            0x6461_6572_6854 => Ok(DataType::Thread),
            0x7974_6974_6e65_6449 => Ok(DataType::Identity),
            0x6572_6f43 => Ok(DataType::Core),
            0x6e6f_6974_7069_7263_7362_7553_6873_7550 => Ok(DataType::PushSubscription),
            0x0074_6570_7069_6e53_6863_7261_6553 => Ok(DataType::SearchSnippet),
            0x6573_6e6f_7073_6552_6e6f_6974_6163_6156 => Ok(DataType::VacationResponse),
            0x004e_444d => Ok(DataType::Mdn),
            0x0061_746f_7551 => Ok(DataType::Quota),
            0x0074_7069_7263_5365_7665_6953 => Ok(DataType::SieveScript),
            _ => Err(parser.error_value()),
        }
    }
}
