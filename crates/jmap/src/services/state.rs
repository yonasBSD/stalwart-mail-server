/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use common::{
    core::BuildServer,
    ipc::{PushSubscription, StateEvent, UpdateSubscription},
    Inner, Server, IPC_CHANNEL_BUFFER,
};
use jmap_proto::types::{id::Id, state::StateChange, type_state::DataType};
use std::future::Future;
use store::ahash::AHashMap;
use tokio::sync::mpsc;
use trc::ServerEvent;
use utils::map::bitmap::Bitmap;

use crate::push::{get::PushSubscriptionFetch, manager::spawn_push_manager};

#[derive(Debug)]
struct Subscriber {
    types: Bitmap<DataType>,
    subscription: SubscriberType,
}

#[derive(Debug)]
pub enum SubscriberType {
    Ipc { tx: mpsc::Sender<StateChange> },
    Push { expires: u64 },
}

impl Subscriber {
    fn is_valid(&self, current_time: u64) -> bool {
        match &self.subscription {
            SubscriberType::Ipc { tx } => !tx.is_closed(),
            SubscriberType::Push { expires } => expires > &current_time,
        }
    }
}

const PURGE_EVERY: Duration = Duration::from_secs(3600);
const SEND_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubscriberId {
    Ipc(u32),
    Push(u32),
}

#[allow(clippy::unwrap_or_default)]
pub fn spawn_state_manager(inner: Arc<Inner>, mut change_rx: mpsc::Receiver<StateEvent>) {
    let push_tx = spawn_push_manager(inner.clone());

    tokio::spawn(async move {
        let mut subscribers: AHashMap<u32, AHashMap<SubscriberId, Subscriber>> =
            AHashMap::default();
        let mut shared_accounts: AHashMap<u32, Vec<u32>> = AHashMap::default();
        let mut shared_accounts_map: AHashMap<u32, AHashMap<u32, Bitmap<DataType>>> =
            AHashMap::default();

        let mut last_purge = Instant::now();

        while let Some(event) = change_rx.recv().await {
            let mut purge_needed = last_purge.elapsed() >= PURGE_EVERY;

            match event {
                StateEvent::Stop => {
                    if push_tx.send(crate::push::Event::Reset).await.is_err() {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push reset.",
                            CausedBy = trc::location!()
                        );
                    }
                    break;
                }
                StateEvent::UpdateSharedAccounts { account_id } => {
                    // Obtain account membership and shared mailboxes
                    let acl = match inner.build_server().get_access_token(account_id).await {
                        Ok(result) => result,
                        Err(err) => {
                            trc::error!(err
                                .account_id(account_id)
                                .details("Failed to obtain access token."));

                            continue;
                        }
                    };

                    // Delete any removed sharings
                    if let Some(shared_account_ids) = shared_accounts.get(&account_id) {
                        for shared_account_id in shared_account_ids {
                            if *shared_account_id != acl.primary_id
                                && !acl.member_of.contains(shared_account_id)
                                && !acl
                                    .access_to
                                    .iter()
                                    .any(|(id, _)| *id == *shared_account_id)
                            {
                                if let Some(shared_list) =
                                    shared_accounts_map.get_mut(shared_account_id)
                                {
                                    shared_list.remove(&account_id);
                                    if shared_list.is_empty() {
                                        shared_accounts_map.remove(shared_account_id);
                                    }
                                }
                            }
                        }
                    }

                    // Update lists
                    let mut shared_account_ids =
                        Vec::with_capacity(acl.member_of.len() + 1 + acl.access_to.len());
                    for member_id in [acl.primary_id].iter().chain(acl.member_of.iter()) {
                        shared_account_ids.push(*member_id);
                        shared_accounts_map
                            .entry(*member_id)
                            .or_insert_with(AHashMap::new)
                            .insert(account_id, Bitmap::all());
                    }
                    for (shared_account_id, shared_collections) in acl.access_to.iter() {
                        let mut types: Bitmap<DataType> = Bitmap::new();
                        for collection in *shared_collections {
                            if let Ok(type_state) = DataType::try_from(collection) {
                                types.insert(type_state);
                                if type_state == DataType::Email {
                                    types.insert(DataType::EmailDelivery);
                                    types.insert(DataType::Thread);
                                }
                            }
                        }
                        if !types.is_empty() {
                            shared_account_ids.push(*shared_account_id);
                            shared_accounts_map
                                .entry(*shared_account_id)
                                .or_insert_with(AHashMap::new)
                                .insert(account_id, types);
                        }
                    }
                    shared_accounts.insert(account_id, shared_account_ids);
                }
                StateEvent::Subscribe {
                    account_id,
                    types,
                    tx,
                } => {
                    subscribers
                        .entry(account_id)
                        .or_insert_with(AHashMap::default)
                        .insert(
                            SubscriberId::Ipc(rand::random()),
                            Subscriber {
                                types,
                                subscription: SubscriberType::Ipc { tx },
                            },
                        );
                }
                StateEvent::Publish { state_change } => {
                    if let Some(shared_accounts) = shared_accounts_map.get(&state_change.account_id)
                    {
                        let current_time = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let mut push_ids = Vec::new();

                        for (owner_account_id, allowed_types) in shared_accounts {
                            if let Some(subscribers) = subscribers.get(owner_account_id) {
                                for (subscriber_id, subscriber) in subscribers {
                                    let mut types = Vec::with_capacity(state_change.types.len());
                                    for (state_type, change_id) in &state_change.types {
                                        if subscriber.types.contains(*state_type)
                                            && allowed_types.contains(*state_type)
                                        {
                                            types.push((*state_type, *change_id));
                                        }
                                    }
                                    if !types.is_empty() {
                                        match &subscriber.subscription {
                                            SubscriberType::Ipc { tx } if !tx.is_closed() => {
                                                let subscriber_tx = tx.clone();
                                                let state_change = state_change.clone();

                                                tokio::spawn(async move {
                                                    // Timeout after 500ms in case there is a blocked client
                                                    if subscriber_tx
                                                        .send_timeout(
                                                            StateChange {
                                                                account_id: state_change.account_id,
                                                                types,
                                                            },
                                                            SEND_TIMEOUT,
                                                        )
                                                        .await
                                                        .is_err()
                                                    {
                                                        trc::event!(
                                                            Server(ServerEvent::ThreadError),
                                                            Details = "Error sending state change to subscriber.",
                                                            CausedBy = trc::location!()
                                                        );
                                                    }
                                                });
                                            }
                                            SubscriberType::Push { expires }
                                                if expires > &current_time =>
                                            {
                                                push_ids.push(Id::from_parts(
                                                    *owner_account_id,
                                                    (*subscriber_id).into(),
                                                ));
                                            }
                                            _ => {
                                                purge_needed = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if !push_ids.is_empty()
                            && push_tx
                                .send(crate::push::Event::Push {
                                    ids: push_ids,
                                    state_change,
                                })
                                .await
                                .is_err()
                        {
                            trc::event!(
                                Server(ServerEvent::ThreadError),
                                Details = "Error sending push updates.",
                                CausedBy = trc::location!()
                            );
                        }
                    }
                }
                StateEvent::UpdateSubscriptions {
                    account_id,
                    subscriptions,
                } => {
                    let mut updated_ids = Vec::with_capacity(subscriptions.len());
                    let mut push_updates = Vec::with_capacity(subscriptions.len());

                    if let Some(subscribers) = subscribers.get_mut(&account_id) {
                        let mut remove_ids = Vec::new();

                        for subscriber_id in subscribers.keys() {
                            if let SubscriberId::Push(push_id) = subscriber_id {
                                if !subscriptions.iter().any(|s| {
                                    matches!(s, UpdateSubscription::Verified(
                                        PushSubscription { id, .. }
                                    ) if id == push_id)
                                }) {
                                    remove_ids.push(*subscriber_id);
                                }
                            }
                        }

                        for remove_id in remove_ids {
                            push_updates.push(crate::push::PushUpdate::Unregister {
                                id: Id::from_parts(account_id, remove_id.into()),
                            });
                            subscribers.remove(&remove_id);
                        }
                    }

                    for subscription in subscriptions {
                        match subscription {
                            UpdateSubscription::Unverified {
                                id,
                                url,
                                code,
                                keys,
                            } => {
                                push_updates.push(crate::push::PushUpdate::Verify {
                                    id,
                                    account_id,
                                    url,
                                    code,
                                    keys,
                                });
                            }
                            UpdateSubscription::Verified(verified) => {
                                updated_ids.push(verified.id);
                                subscribers
                                    .entry(account_id)
                                    .or_insert_with(AHashMap::default)
                                    .insert(
                                        SubscriberId::Push(verified.id),
                                        Subscriber {
                                            types: verified.types,
                                            subscription: SubscriberType::Push {
                                                expires: verified.expires,
                                            },
                                        },
                                    );

                                push_updates.push(crate::push::PushUpdate::Register {
                                    id: Id::from_parts(account_id, verified.id),
                                    url: verified.url,
                                    keys: verified.keys,
                                });
                            }
                        }
                    }

                    if !push_updates.is_empty()
                        && push_tx
                            .send(crate::push::Event::Update {
                                updates: push_updates,
                            })
                            .await
                            .is_err()
                    {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push updates.",
                            CausedBy = trc::location!()
                        );
                    }
                }
            }

            if purge_needed {
                let mut remove_account_ids = Vec::new();
                let current_time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                for (account_id, subscriber_map) in &mut subscribers {
                    let mut remove_subscription_ids = Vec::new();
                    for (id, subscriber) in subscriber_map.iter() {
                        if !subscriber.is_valid(current_time) {
                            remove_subscription_ids.push(*id);
                        }
                    }
                    if !remove_subscription_ids.is_empty() {
                        if remove_subscription_ids.len() < subscriber_map.len() {
                            for remove_subscription_id in remove_subscription_ids {
                                subscriber_map.remove(&remove_subscription_id);
                            }
                        } else {
                            remove_account_ids.push(*account_id);
                        }
                    }
                }

                for remove_account_id in remove_account_ids {
                    subscribers.remove(&remove_account_id);
                }

                last_purge = Instant::now();
            }
        }
    });
}

pub trait StateManager: Sync + Send {
    fn subscribe_state_manager(
        &self,
        account_id: u32,
        types: Bitmap<DataType>,
    ) -> impl Future<Output = trc::Result<mpsc::Receiver<StateChange>>> + Send;

    fn update_push_subscriptions(&self, account_id: u32) -> impl Future<Output = bool> + Send;
}

impl StateManager for Server {
    async fn subscribe_state_manager(
        &self,
        account_id: u32,
        types: Bitmap<DataType>,
    ) -> trc::Result<mpsc::Receiver<StateChange>> {
        let (change_tx, change_rx) = mpsc::channel::<StateChange>(IPC_CHANNEL_BUFFER);
        let state_tx = self.inner.ipc.state_tx.clone();

        for event in [
            StateEvent::UpdateSharedAccounts { account_id },
            StateEvent::Subscribe {
                account_id,
                types,
                tx: change_tx,
            },
        ] {
            state_tx.send(event).await.map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .caused_by(trc::location!())
            })?;
        }

        Ok(change_rx)
    }

    async fn update_push_subscriptions(&self, account_id: u32) -> bool {
        let push_subs = match self.fetch_push_subscriptions(account_id).await {
            Ok(push_subs) => push_subs,
            Err(err) => {
                trc::error!(err
                    .account_id(account_id)
                    .details("Failed to fetch push subscriptions"));
                return false;
            }
        };

        let state_tx = self.inner.ipc.state_tx.clone();
        for event in [StateEvent::UpdateSharedAccounts { account_id }, push_subs] {
            if state_tx.send(event).await.is_err() {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Details = "Error sending state change.",
                    CausedBy = trc::location!()
                );

                return false;
            }
        }

        true
    }
}

impl From<SubscriberId> for u32 {
    fn from(subscriber_id: SubscriberId) -> u32 {
        match subscriber_id {
            SubscriberId::Ipc(id) => id,
            SubscriberId::Push(id) => id,
        }
    }
}
