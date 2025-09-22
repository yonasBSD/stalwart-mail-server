/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::parser::{JsonObjectParser, json::Parser};
use types::acl::Acl;

impl JsonObjectParser for Acl {
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
            0x6461_6572 => Ok(Acl::Read),
            0x7966_6964_6f6d => Ok(Acl::Modify),
            0x6574_656c_6564 => Ok(Acl::Delete),
            0x0073_6d65_7449_6461_6572 => Ok(Acl::ReadItems),
            0x736d_6574_4964_6461 => Ok(Acl::AddItems),
            0x0073_6d65_7449_7966_6964_6f6d => Ok(Acl::ModifyItems),
            0x0073_6d65_7449_6576_6f6d_6572 => Ok(Acl::RemoveItems),
            0x0064_6c69_6843_6574_6165_7263 => Ok(Acl::CreateChild),
            0x7265_7473_696e_696d_6461 => Ok(Acl::Administer),
            0x7469_6d62_7573 => Ok(Acl::Submit),
            _ => Err(parser.error_value()),
        }
    }
}
