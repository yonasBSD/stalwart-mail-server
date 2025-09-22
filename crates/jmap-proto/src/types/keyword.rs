/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::parser::{JsonObjectParser, json::Parser};
use types::keyword::Keyword;

impl JsonObjectParser for Keyword {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let pos = parser.pos;
        if parser
            .next_unescaped()?
            .ok_or_else(|| parser.error_value())?
            == b'$'
        {
            let mut hash = 0;
            let mut shift = 0;

            while let Some(ch) = parser.next_unescaped()? {
                if shift < 128 {
                    hash |= (ch as u128) << shift;
                    shift += 8;
                } else {
                    break;
                }
            }

            match hash {
                0x6e65_6573 => return Ok(Keyword::Seen),
                0x0074_6661_7264 => return Ok(Keyword::Draft),
                0x0064_6567_6761_6c66 => return Ok(Keyword::Flagged),
                0x6465_7265_7773_6e61 => return Ok(Keyword::Answered),
                0x746e_6563_6572 => return Ok(Keyword::Recent),
                0x0074_6e61_7472_6f70_6d69 => return Ok(Keyword::Important),
                0x676e_6968_7369_6870 => return Ok(Keyword::Phishing),
                0x6b6e_756a => return Ok(Keyword::Junk),
                0x006b_6e75_6a74_6f6e => return Ok(Keyword::NotJunk),
                0x0064_6574_656c_6564 => return Ok(Keyword::Deleted),
                0x0064_6564_7261_7772_6f66 => return Ok(Keyword::Forwarded),
                0x0074_6e65_736e_646d => return Ok(Keyword::MdnSent),
                _ => (),
            }
        }

        if parser.is_eof || parser.skip_string() {
            Ok(Keyword::Other(
                String::from_utf8_lossy(parser.bytes[pos..parser.pos - 1].as_ref()).into_owned(),
            ))
        } else {
            Err(parser.error_unterminated())
        }
    }
}
