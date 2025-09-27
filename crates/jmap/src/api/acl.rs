/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::auth::AccessToken;
use jmap_proto::object::{JmapObject, JmapRight};
use jmap_tools::{Key, Map, Value};
use types::{
    acl::{Acl, AclGrant},
    id::Id,
};
use utils::map::bitmap::Bitmap;

pub struct JmapRights;

impl JmapRights {
    pub fn all_rights<T: JmapObject>() -> Value<'static, T::Property, T::Element> {
        let rights = T::Right::all_rights();
        let mut obj = Map::with_capacity(rights.len());

        for right in rights {
            obj.insert_unchecked(Key::Property((*right).into()), Value::Bool(true));
        }

        Value::Object(obj)
    }

    pub fn rights<T: JmapObject>(acls: Bitmap<Acl>) -> Value<'static, T::Property, T::Element> {
        let mut obj = Map::with_capacity(3);

        for acl in acls.into_iter() {
            for right in T::Right::from_acl(acl) {
                obj.insert_unchecked(Key::Property((*right).into()), Value::Bool(true));
            }
        }

        Value::Object(obj)
    }

    pub fn share_with<T: JmapObject>(
        account_id: u32,
        access_token: &AccessToken,
        grants: &[AclGrant],
    ) -> Value<'static, T::Property, T::Element> {
        if access_token.is_member(account_id)
            || grants.iter().any(|item| {
                access_token.is_member(item.account_id) && item.grants.contains(Acl::Administer)
            })
        {
            let mut share_with = Map::with_capacity(grants.len());
            for grant in grants {
                share_with.insert_unchecked(
                    Key::Owned(Id::from(grant.account_id).to_string()),
                    Self::rights::<T>(grant.grants),
                );
            }

            Value::Object(share_with)
        } else {
            Value::Null
        }
    }
}
