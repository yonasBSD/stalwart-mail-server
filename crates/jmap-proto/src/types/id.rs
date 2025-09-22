/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::parser::{JsonObjectParser, json::Parser};
use types::id::Id;
use utils::codec::base32_custom::BASE32_INVERSE;

impl JsonObjectParser for Id {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut id = 0;

        while let Some(ch) = parser.next_unescaped()? {
            let i = BASE32_INVERSE[ch as usize];
            if i != u8::MAX {
                id = (id << 5) | i as u64;
            } else {
                return Err(parser.error_value());
            }
        }

        Ok(Id::new(id))
    }
}

#[cfg(test)]
mod tests {
    use crate::{parser::json::Parser, types::id::Id};

    #[test]
    fn parse_jmap_id() {
        for number in [
            0,
            1,
            10,
            1000,
            Id::singleton().id(),
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let id = Id::from(number);
            assert_eq!(
                Parser::new(format!("\"{id}\"").as_bytes())
                    .next_token::<Id>()
                    .unwrap()
                    .unwrap_string("")
                    .unwrap(),
                id
            );
        }

        Parser::new(b"\"p333333333333p333333333333\"")
            .next_token::<Id>()
            .unwrap()
            .unwrap_string("")
            .unwrap();
    }
}
