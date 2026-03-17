/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use common::Server;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    object::registry::RegistryComparator,
    types::state::State,
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, RegistryJsonPatch},
    pickle::Pickle,
    schema::{
        enums::{TaskStatusType, TaskType},
        prelude::{Object, Property},
        structs::Task,
    },
    types::{
        EnumImpl, ObjectImpl,
        datetime::UTCDateTime,
        index::{IndexBuilder, IndexKey},
    },
};
use services::task_manager::lock::TaskLockManager;
use std::str::FromStr;
use store::{
    IterateParams, SerializeInfallible, U64_LEN, ValueKey,
    registry::RegistryFilterOp,
    write::{BatchBuilder, RegistryClass, TaskQueueClass, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::id::Id;

pub(crate) async fn task_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    let mut batch = BatchBuilder::new();
    let mut locked_tasks = Vec::new();

    // Process creations
    'outer: for (id, value) in set.create.drain() {
        let mut task = Task::default();
        if let Err(err) = task.patch(
            JsonPointerPatch::new(&JsonPointer::new(vec![]))
                .with_create(true)
                .with_can_set_account(true),
            value,
        ) {
            set.response.not_created.append(id, err.into());
            continue 'outer;
        }

        let mut validation_errors = Vec::new();
        if !task.validate(&mut validation_errors) {
            set.response.not_created.append(
                id,
                SetError::new(SetErrorType::ValidationFailed)
                    .with_validation_errors(validation_errors),
            );
            continue 'outer;
        }

        if !set.access_token.has_permission(task.permission()) {
            set.response.not_created.append(
                id,
                SetError::forbidden().with_description(format!(
                    "Insufficient permissions to create task of type {}",
                    task.object_type().as_str()
                )),
            );
            continue 'outer;
        }

        let task_type = task.object_type();
        match task_type {
            TaskType::IndexDocument
            | TaskType::UnindexDocument
            | TaskType::IndexTrace
            | TaskType::AccountMaintenance
            | TaskType::StoreMaintenance
            | TaskType::SpamFilterMaintenance => {
                let mut index = IndexBuilder::default();
                task.index(&mut index);

                // Validate foreign keys
                for key in index.keys {
                    if let IndexKey::ForeignKey {
                        object_id: foreign_id,
                        ..
                    } = key
                        && !set
                            .server
                            .store()
                            .key_exists(ValueKey::from(ValueClass::Registry(
                                RegistryClass::IndexId {
                                    object_id: foreign_id.object().to_id(),
                                    item_id: foreign_id.id().id(),
                                },
                            )))
                            .await
                            .caused_by(trc::location!())?
                    {
                        set.response.not_created.append(
                            id,
                            SetError::new(SetErrorType::InvalidForeignKey)
                                .with_object_id(foreign_id),
                        );
                        continue 'outer;
                    }
                }

                let task_id = set.server.registry().assign_id();
                batch.schedule_task_with_id(task_id, task).commit_point();
                set.response.created(id, task_id);
            }
            TaskType::CalendarAlarmEmail
            | TaskType::CalendarAlarmNotification
            | TaskType::CalendarItipMessage
            | TaskType::MergeThreads
            | TaskType::DmarcReport
            | TaskType::TlsReport
            | TaskType::DestroyAccount
            | TaskType::RestoreArchivedItem => {
                set.response.not_created.append(
                    id,
                    SetError::forbidden().with_description(format!(
                        "{} is an internal task type that cannot be created by clients",
                        task_type.as_str()
                    )),
                );
            }
        }
    }

    // Process updates
    'outer: for (id, value) in set.update.drain(..) {
        let task_id = id.id();
        let Some(mut task) = set
            .server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task { id: task_id },
            )))
            .await?
        else {
            set.response.not_updated.append(id, SetError::not_found());
            continue;
        };

        if !set.access_token.has_permission(task.permission()) {
            set.response.not_updated.append(
                id,
                SetError::forbidden().with_description(format!(
                    "Insufficient permissions to update task of type {}",
                    task.object_type().as_str()
                )),
            );
            continue 'outer;
        }

        if !set.server.try_lock_task(task_id).await {
            set.response.not_updated.append(
                id,
                SetError::forbidden().with_description(
                    "Task is currently being processed and cannot be updated".to_string(),
                ),
            );
            continue;
        }
        locked_tasks.push(task_id);

        let old_timestamp = task.due_timestamp();
        let old_status = task.status().clone();
        for (key, value) in value.into_expanded_object() {
            let ptr = match key {
                Key::Property(prop) => {
                    JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                }
                Key::Borrowed(other) => JsonPointer::parse(other),
                Key::Owned(other) => JsonPointer::parse(&other),
            };

            if let Err(err) = task.patch(
                JsonPointerPatch::new(&ptr)
                    .with_create(false)
                    .with_can_set_account(true),
                value,
            ) {
                set.response.not_updated.append(id, err.into());
                continue 'outer;
            }
        }

        if task.status() != &old_status {
            let timestamp = task.due_timestamp();
            if timestamp != old_timestamp {
                batch
                    .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                        id: task_id,
                        due: old_timestamp,
                    }))
                    .set(
                        ValueClass::TaskQueue(TaskQueueClass::Due {
                            id: task_id,
                            due: timestamp,
                        }),
                        task.object_type().to_id().serialize(),
                    );
            }

            batch
                .set(
                    ValueClass::TaskQueue(TaskQueueClass::Task { id: task_id }),
                    task.to_pickled_vec(),
                )
                .commit_point();
        }
    }

    // Process destructions
    for id in set.destroy.drain(..) {
        let task_id = id.id();
        let Some(task) = set
            .server
            .store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task { id: task_id },
            )))
            .await?
        else {
            set.response.not_destroyed.append(id, SetError::not_found());
            continue;
        };

        if !set.access_token.has_permission(task.permission()) {
            set.response.not_destroyed.append(
                id,
                SetError::forbidden().with_description(format!(
                    "Insufficient permissions to destroy task of type {}",
                    task.object_type().as_str()
                )),
            );
            continue;
        }

        if !set.server.try_lock_task(task_id).await {
            set.response.not_destroyed.append(
                id,
                SetError::forbidden().with_description(
                    "Task is currently being processed and cannot be destroyed".to_string(),
                ),
            );
            continue;
        }
        locked_tasks.push(task_id);

        let due = task.due_timestamp();

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        if let Task::DestroyAccount(task) = task {
            use crate::registry::set::map_write_error;
            use registry::schema::{
                enums::AccountType,
                structs::{Account, GroupAccount, UserAccount},
            };
            use store::registry::write::{RegistryWrite, RegistryWriteResult};

            if !set.server.is_enterprise_edition() {
                set.response.not_destroyed.append(
                    id,
                    SetError::forbidden().with_description(
                        "Account recovery is not supported in this deployment".to_string(),
                    ),
                );
                continue;
            }

            let object = match task.account_type {
                AccountType::User => Account::User(UserAccount {
                    name: task.account_name,
                    domain_id: task.account_domain_id,
                    ..Default::default()
                }),
                AccountType::Group => Account::Group(GroupAccount {
                    name: task.account_name,
                    domain_id: task.account_domain_id,
                    ..Default::default()
                }),
            }
            .into();

            match set
                .server
                .registry()
                .write(RegistryWrite::insert_with_id(task.account_id, &object))
                .await?
            {
                RegistryWriteResult::Success(_) => {}
                err => {
                    set.response.not_destroyed.append(
                        id,
                        map_write_error(err).with_description("Account recovery failed"),
                    );
                    continue;
                }
            }
        }
        // SPDX-SnippetEnd

        #[cfg(not(feature = "enterprise"))]
        {
            set.response.not_destroyed.append(
                id,
                SetError::forbidden().with_description(
                    "Account recovery is not supported in this deployment".to_string(),
                ),
            );
            continue;
        }

        batch
            .clear(ValueClass::TaskQueue(TaskQueueClass::Task { id: task_id }))
            .clear(ValueClass::TaskQueue(TaskQueueClass::Due {
                id: task_id,
                due,
            }))
            .commit_point();
    }

    if !batch.is_empty() {
        set.server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        set.server.notify_task_queue();
    }

    for task_id in locked_tasks {
        set.server.remove_index_lock(task_id).await;
    }

    Ok(set)
}

pub(crate) async fn task_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        task_ids(get.server, get.server.core.jmap.get_max_objects).await?
    };

    for id in ids {
        if let Some(task) = get
            .server
            .store()
            .get_value::<Object>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task { id: id.id() },
            )))
            .await?
        {
            get.insert(id, task.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn task_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut due_from = 0u64;
    let mut due_to = u64::MAX;

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Due => {
                if let Some(due) = value.as_str().and_then(|s| UTCDateTime::from_str(s).ok()) {
                    let due = due.timestamp() as u64;
                    let (from, to) = match op {
                        RegistryFilterOp::Equal => (due, due),
                        RegistryFilterOp::GreaterThan => (due + 1, u64::MAX),
                        RegistryFilterOp::GreaterEqualThan => (due, u64::MAX),
                        RegistryFilterOp::LowerThan => (0, due - 1),
                        RegistryFilterOp::LowerEqualThan => (0, due),
                        _ => return false,
                    };

                    // Intersect with existing range
                    due_from = due_from.max(from);
                    due_to = due_to.min(to);

                    due_from <= due_to
                } else {
                    false
                }
            }
            Property::Status => {
                if let Some(typ) = value.as_str().and_then(TaskStatusType::parse) {
                    if typ == TaskStatusType::Failed {
                        due_from = u64::MAX;
                        due_to = u64::MAX;
                    }
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    if req
        .request
        .sort
        .as_ref()
        .and_then(|sort| sort.first())
        .is_some_and(|comp| !matches!(comp.property, RegistryComparator::Property(Property::Due)))
    {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Only sorting by 'due' is supported for tasks".to_string()));
    }

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;

    // Build response
    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    if response.response.total.is_some() {
        response.response.total = Some(0);
    }

    let from_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
        id: 0,
        due: due_from,
    }));
    let to_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
        id: u64::MAX,
        due: due_to,
    }));

    req.server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key)
                .set_ascending(params.sort_ascending)
                .no_values(),
            |key, _| {
                let id = key.deserialize_be_u64(U64_LEN)?;
                if let Some(total) = response.response.total.as_mut() {
                    *total += 1;
                    if !response.is_full() {
                        response.add_id(id.into());
                    }
                    Ok(true)
                } else {
                    Ok(response.add_id(id.into()))
                }
            },
        )
        .await
        .caused_by(trc::location!())?;

    if let (Some(total), Some(limit)) = (response.response.total, response.response.limit)
        && total < limit
    {
        response.response.limit = None;
    }

    Ok(response)
}

async fn task_ids(server: &Server, max_results: usize) -> trc::Result<Vec<Id>> {
    let mut tasks = Vec::with_capacity(8);
    let from_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due { id: 0, due: 0 }));
    let to_key = ValueKey::from(ValueClass::TaskQueue(TaskQueueClass::Due {
        id: u64::MAX,
        due: u64::MAX,
    }));

    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                tasks.push(key.deserialize_be_u64(U64_LEN)?.into());

                Ok(tasks.len() < max_results)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| tasks)
}
