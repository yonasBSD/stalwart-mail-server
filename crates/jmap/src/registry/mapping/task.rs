/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{RegistryGetResponse, RegistrySetResponse};
use common::Server;
use jmap_proto::error::set::{SetError, SetErrorType};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, RegistryJsonPatch},
    pickle::Pickle,
    schema::{enums::TaskType, prelude::Object, structs::Task},
    types::{
        EnumImpl, ObjectImpl,
        index::{IndexBuilder, IndexKey},
    },
};
use services::task_manager::lock::TaskLockManager;
use store::{
    IterateParams, SerializeInfallible, U64_LEN, ValueKey,
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
        for (key, value) in value.into_expanded_object() {
            let Key::Property(prop) = key else {
                set.response.not_created.append(
                    id,
                    SetError::invalid_properties().with_property(key.into_owned()),
                );
                continue 'outer;
            };
            let ptr = JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))]);
            if let Err(err) = task.patch(JsonPointerPatch::new(&ptr).with_create(false), value) {
                set.response.not_created.append(id, err.into());
                continue 'outer;
            }
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
                        && set
                            .server
                            .store()
                            .get_value::<()>(ValueKey::from(ValueClass::Registry(
                                RegistryClass::IndexId {
                                    object_id: foreign_id.object().to_id(),
                                    item_id: foreign_id.id().id(),
                                },
                            )))
                            .await
                            .caused_by(trc::location!())?
                            .is_none()
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

            if let Err(err) = task.patch(JsonPointerPatch::new(&ptr).with_create(false), value) {
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

async fn task_ids(server: &Server, max_results: usize) -> trc::Result<Vec<Id>> {
    let mut events = Vec::with_capacity(8);

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
                events.push(key.deserialize_be_u64(U64_LEN)?.into());

                Ok(events.len() < max_results)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| events)
}
