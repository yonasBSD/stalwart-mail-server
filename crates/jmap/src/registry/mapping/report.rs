/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{RegistryGetResponse, RegistrySetResponse};
use common::Server;
use jmap_proto::error::set::SetError;
use jmap_tools::{Key, Value};
use registry::{
    jmap::IntoValue,
    schema::prelude::{Object, ObjectInner, ObjectType, Property},
    types::{EnumImpl, datetime::UTCDateTime},
};
use smtp::reporting::index::{ExternalReportIndex, InternalReportIndex};
use std::str::FromStr;
use store::{
    IterateParams, U16_LEN, ValueKey,
    ahash::AHashSet,
    registry::RegistryQuery,
    write::{BatchBuilder, RegistryClass, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::id::Id;

pub(crate) async fn report_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    let object_id = set.object_type.to_id();

    // Reports cannot be created
    set.fail_all_create("Reports cannot be created");

    let mut batch = BatchBuilder::new();
    if matches!(
        set.object_type,
        ObjectType::DmarcInternalReport | ObjectType::TlsInternalReport
    ) {
        let now = UTCDateTime::now();
        'outer: for (id, value) in set.update.drain(..) {
            // Extract new deliverAt value
            let mut deliver_at = None;
            for (key, value) in value.into_expanded_object() {
                match (key, value) {
                    (Key::Property(Property::DeliverAt), Value::Str(deliver_at_)) => {
                        deliver_at = UTCDateTime::from_str(deliver_at_.as_ref())
                            .ok()
                            .filter(|da| *da > now);
                        if deliver_at.is_none() {
                            set.response.not_updated.append(
                                id,
                                SetError::invalid_patch()
                                    .with_property(Property::DeliverAt)
                                    .with_description("Invalid value for property"),
                            );
                            continue 'outer;
                        }
                    }
                    (Key::Property(Property::Id), _) => {}
                    (key, _) => {
                        set.response.not_updated.append(
                            id,
                            SetError::invalid_properties().with_property(key.into_owned()),
                        );
                        continue 'outer;
                    }
                }
            }
            let Some(deliver_at) = deliver_at else {
                set.response.not_updated.append(
                    id,
                    SetError::invalid_patch()
                        .with_property(Key::Property(Property::DeliverAt))
                        .with_description("Missing required property"),
                );
                continue;
            };

            let item_id = id.id();
            let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
            if let Some(mut report_obj) = set
                .server
                .store()
                .get_value::<Object>(ValueKey::from(key.clone()))
                .await?
            {
                match &mut report_obj.inner {
                    ObjectInner::DmarcInternalReport(report) => {
                        report.reschedule_ops(&mut batch, item_id, report_obj.revision, deliver_at);
                    }
                    ObjectInner::TlsInternalReport(report) => {
                        report.reschedule_ops(&mut batch, item_id, report_obj.revision, deliver_at);
                    }
                    _ => {}
                }
                batch.commit_point();

                set.response.updated.append(id, None);
            } else {
                set.response.not_updated.append(id, SetError::not_found());
            }
        }
    } else {
        // External reports cannot be updated
        set.fail_all_update("External reports cannot be updated");
    }

    // Process reports to destroy
    let tenant_id = set.access_token.tenant_id().map(Id::from);
    for id in set.destroy.drain(..) {
        let item_id = id.id();
        let key = ValueClass::Registry(RegistryClass::Item { object_id, item_id });
        if let Some(report) = set
            .server
            .store()
            .get_value::<Object>(ValueKey::from(key.clone()))
            .await?
            .filter(|report| {
                !set.is_tenant_filtered || report.inner.member_tenant_id() == tenant_id
            })
        {
            match &report.inner {
                ObjectInner::DmarcExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::TlsExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::ArfExternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::DmarcInternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                ObjectInner::TlsInternalReport(report) => {
                    report.write_ops(&mut batch, item_id, false);
                }
                _ => {}
            }
            batch.commit_point();

            set.response.destroyed.push(id);
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    if !batch.is_empty() {
        set.server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(set)
}

pub(crate) async fn report_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let object_id = get.object_type.to_id();
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else if matches!(
        get.object_type,
        ObjectType::DmarcExternalReport
            | ObjectType::TlsExternalReport
            | ObjectType::ArfExternalReport
    ) {
        if get.is_tenant_filtered {
            get.server.registry().query::<AHashSet<u64>>(
                RegistryQuery::new(get.object_type).with_tenant(get.access_token.tenant_id()),
            )
        } else {
            get.server.registry().query::<AHashSet<u64>>(
                RegistryQuery::new(get.object_type).greater_than(Property::ExpiresAt, 0u64),
            )
        }
        .await?
        .into_iter()
        .take(get.server.core.jmap.get_max_objects)
        .map(Id::from)
        .collect()
    } else {
        internal_report_ids(get.server, object_id, get.server.core.jmap.get_max_objects).await?
    };

    let tenant_id = get.access_token.tenant_id().map(Id::from);
    for id in ids {
        if let Some(report) = get
            .server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::Registry(RegistryClass::Item {
                object_id,
                item_id: id.id(),
            })))
            .await?
            .filter(|report| {
                !get.is_tenant_filtered || report.inner.member_tenant_id() == tenant_id
            })
        {
            get.insert(id, report.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

async fn internal_report_ids(
    server: &Server,
    object_id: u16,
    max_results: usize,
) -> trc::Result<Vec<Id>> {
    let mut events = Vec::with_capacity(8);

    let from_key = ValueKey::from(ValueClass::Registry(RegistryClass::PrimaryKey {
        object_id: object_id.into(),
        index_id: Property::Domain.to_id(),
        key: vec![],
    }));
    let to_key = ValueKey::from(ValueClass::Registry(RegistryClass::PrimaryKey {
        object_id: object_id.into(),
        index_id: Property::Domain.to_id(),
        key: vec![
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
            u8::MAX,
        ],
    }));

    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                if !value.is_empty() {
                    events.push(key.deserialize_be_u64(U16_LEN)?.into());
                }

                Ok(events.len() < max_results)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| events)
}
