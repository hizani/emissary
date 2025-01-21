// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::{
    crypto::{base32_encode, base64_encode, StaticPublicKey},
    error::{Error, QueryError},
    i2np::{
        database::{
            lookup::{DatabaseLookup, DatabaseLookupBuilder, LookupType, ReplyType},
            search_reply::DatabaseSearchReply,
            store::{
                DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload,
                ReplyType as StoreReplyType,
            },
        },
        delivery_status::DeliveryStatus,
        tunnel::gateway::TunnelGateway,
        Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::{dht::Dht, handle::NetDbActionRecycle, metrics::*},
    primitives::{Lease, LeaseSet2, RouterId, RouterInfo, TunnelId},
    profile::{Bucket, ProfileStorage},
    runtime::{Counter, Gauge, JoinSet, MetricType, MetricsHandle, Runtime},
    subsystem::SubsystemEvent,
    transport::TransportService,
    tunnel::{TunnelPoolEvent, TunnelPoolHandle, TunnelSender},
};

use bytes::{Bytes, BytesMut};
use futures::{future::BoxFuture, FutureExt, StreamExt};
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc;

use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub use handle::NetDbHandle;

#[cfg(test)]
pub use handle::NetDbAction;
#[cfg(not(test))]
use handle::NetDbAction;

mod bucket;
mod dht;
mod handle;
mod metrics;
mod routing_table;
mod types;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::netdb";

/// `NetDb` query timeout.
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Router info republish timeout.
const ROUTER_INFO_REPUBLISH_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// [`NetDb`] maintenance interval.
const NETDB_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);

/// Number of router hashes to include into [`DatabaseSearchReply`].
const SEARCH_REPLY_NUM_ROUTERS: usize = 5usize;

/// Local router info publisher.
///
/// Publishes the router info of the local router first when the router boots up and after that
/// periodically (1h) to prevent the router from disappearing from the global NetDb.
///
/// [`RouterInfoPublisher`] implements `Future` which fires periodically and instructs [`NetDb`] to
/// call [`RouterInfoPublisher::publish()`] to get a `DatabaseStore` message and a `RouterId` of a
/// floodfill to whom the message should be sent.
pub struct RouterInfoPublisher<R> {
    /// Local router ID.
    router_id: RouterId,

    /// Serialized [`RouterId`] of the local router.
    serialized_router_id: Bytes,

    /// Serialized [`RouterInfo`] of the local router.
    serialized_router_info: Bytes,

    /// Republish timer.
    timer: BoxFuture<'static, ()>,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> RouterInfoPublisher<R> {
    /// Create new [`RouterInfoPublisher`].
    fn new(router_id: RouterId, serialized_router_info: Bytes) -> Self {
        let serialized_router_id = Bytes::from(router_id.to_vec());

        // gzip-compress the serialized router info, as required by the spec
        //
        // call is expected to succeed as the router info is created by emissary
        let serialized_router_info =
            Bytes::from(R::gzip_compress(serialized_router_info).expect("to succeed"));

        Self {
            router_id,
            serialized_router_id,
            serialized_router_info,
            timer: Box::pin(R::delay(Duration::from_secs(10))),
            _runtime: Default::default(),
        }
    }

    /// Publish local router info to global NetDb.
    ///
    /// Fetches the closest floodfill to our key from `dht` and returns a DatabaseStore message
    /// which [`NetDb`] needs to send to the selected floofill. Returns also the reply token that
    /// was used in the DatabaseStore message, allowing [`NetDb`] to associate the response with the
    /// router info publish.
    ///
    /// Returns `None` if there are no floodfills.
    fn publish(&self) -> (u32, Vec<u8>) {
        let reply_token = R::rng().next_u32();
        let message = DatabaseStoreBuilder::new(
            self.serialized_router_id.clone(),
            DatabaseStoreKind::RouterInfo {
                router_info: self.serialized_router_info.clone(),
            },
        )
        .with_reply_type(StoreReplyType::Router {
            reply_token,
            router_id: self.router_id.clone(),
        })
        .build();

        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseStore)
            .with_message_id(R::rng().next_u32())
            .with_payload(&message)
            .build();

        (reply_token, message)
    }
}

impl<R: Runtime> Future for RouterInfoPublisher<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        futures::ready!(self.timer.poll_unpin(cx));

        // reset timer and poll it to register it into the executor
        {
            self.timer = Box::pin(R::delay(ROUTER_INFO_REPUBLISH_TIMEOUT));
            let _ = self.timer.poll_unpin(cx);
        }

        Poll::Ready(())
    }
}

/// Tunnel selector.
///
/// Distributes tunnel usage fairly across all tunnels.
struct TunnelSelector<T: Clone> {
    /// Iterator index.
    iterator: usize,

    /// Tunnels.
    tunnels: Vec<T>,
}

impl<T: Clone> TunnelSelector<T> {
    /// Create new [`TunnelSelector`].
    pub fn new() -> Self {
        Self {
            iterator: 0usize,
            tunnels: Vec::new(),
        }
    }

    /// Add `tunnel` into [`TunnelSelector`].
    pub fn add_tunnel(&mut self, tunnel: T) {
        self.tunnels.push(tunnel);
    }

    /// Remove tunnel from [`TunnelSelector`] using predicate.
    pub fn remove_tunnel(&mut self, predicate: impl Fn(&T) -> bool) {
        self.tunnels.retain(|tunnel| predicate(tunnel))
    }

    /// Get next tunnel from [`TunnelSelector`], if any exists.
    pub fn next_tunnel(&mut self) -> Option<T> {
        if self.tunnels.is_empty() {
            return None;
        }

        let index = {
            let index = self.iterator;
            self.iterator = self.iterator.wrapping_add(1usize);

            index
        };

        Some(self.tunnels[index % self.tunnels.len()].clone())
    }
}

/// Message kind.
#[derive(Clone)]
enum MessageKind {
    /// Expiring message, e.g., flooded [`DatabaseStore`] for a [`LeaseSet2`] or [`RouterInfo`].
    Expiring {
        /// Serialized I2NP message.
        message: Vec<u8>,

        /// When does the payload of the message expires.
        expires: Duration,
    },

    /// Non-expiring message, e.g, router exploration.
    NonExpiring {
        /// Serialized I2NP message.
        message: Vec<u8>,
    },
}

impl MessageKind {
    /// Convert [`MessageKind`] into serialized I2NP message.
    pub fn into_inner(self) -> Vec<u8> {
        match self {
            Self::Expiring { message, .. } => message,
            Self::NonExpiring { message } => message,
        }
    }
}

/// Routere state.
enum RouterState {
    /// Router is connected.
    Connected,

    /// Router is being dialed.
    Dialing {
        /// Pending messages.
        pending_messages: Vec<MessageKind>,
    },
}

impl fmt::Debug for RouterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => f.debug_struct("RouterState::Connected").finish(),
            Self::Dialing { pending_messages } => f
                .debug_struct("RouterState::Dialing")
                .field("num_pending", &pending_messages.len())
                .finish(),
        }
    }
}

/// Query kind.
enum QueryKind {
    /// Leaseset query.
    Leaseset {
        /// Oneshot sender for sending the result to caller.
        tx: oneshot::Sender<Result<LeaseSet2, QueryError>>,
    },

    /// Router exploration.
    Exploration,

    /// Router info lookup.
    Router,
}

impl fmt::Debug for QueryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Leaseset { .. } => f.debug_struct("QueryKind::LeaseSet").finish_non_exhaustive(),
            Self::Exploration => f.debug_struct("QueryKind::Exploration").finish(),
            Self::Router => f.debug_struct("QueryKind::Router").finish(),
        }
    }
}

/// Network database (NetDB).
pub struct NetDb<R: Runtime> {
    /// Active queries.
    active: HashMap<Bytes, QueryKind>,

    /// DHT of floodfills.
    floodfill_dht: Dht<R>,

    /// DHT of non-floodfill routers.
    ///
    /// Available only if the router is acting as a floodfill router.
    ///
    /// Used to answer router exploration queries.
    router_dht: Option<Dht<R>>,

    /// Exploratory tunnel pool handle.
    exploratory_pool_handle: TunnelPoolHandle,

    /// Has the router been configured to act as a floodfill router.
    floodfill: bool,

    /// Connected routers.
    routers: HashMap<RouterId, RouterState>,

    /// RX channel for receiving queries from other subsystems.
    handle_rx: mpsc::Receiver<NetDbAction, NetDbActionRecycle>,

    /// Active inbound tunnels.
    inbound_tunnels: TunnelSelector<Lease>,

    /// Serialized [`LeasSet2`]s received via `DatabaseStore` messages.
    ///
    /// This contains entries only if `floodfill` is true.
    lease_sets: HashMap<Bytes, (Bytes, Duration)>,

    /// Local router ID.
    local_router_id: RouterId,

    /// `NetDb` maintenance timer.
    maintenance_timer: BoxFuture<'static, ()>,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    // Network ID.
    net_id: u8,

    /// RX channel for receiving NetDb-related messages from [`TunnelManager`].
    netdb_msg_rx: mpsc::Receiver<Message>,

    /// Active inbound tunhnels
    outbound_tunnels: TunnelSelector<TunnelId>,

    /// Profile storage.
    profile_storage: ProfileStorage<R>,

    /// Query timers.
    query_timers: R::JoinSet<Bytes>,

    /// Local router info publishers.
    router_info_publishers: RouterInfoPublisher<R>,

    /// Serialized [`RouterInfo`]s received via `DatabaseStore` messages.
    ///
    /// This contains entries only if `floodfill` is true.
    router_infos: HashMap<Bytes, (Bytes, Duration)>,

    /// Transport service.
    service: TransportService<R>,
}

impl<R: Runtime> NetDb<R> {
    /// Create new [`NetDb`].
    pub fn new(
        local_router_id: RouterId,
        floodfill: bool,
        service: TransportService<R>,
        profile_storage: ProfileStorage<R>,
        metrics: R::MetricsHandle,
        exploratory_pool_handle: TunnelPoolHandle,
        net_id: u8,
        netdb_msg_rx: mpsc::Receiver<Message>,
        local_router_info: Bytes,
    ) -> (Self, NetDbHandle) {
        let floodfills = profile_storage
            .get_router_ids(Bucket::Any, |_, info, _| info.is_floodfill())
            .into_iter()
            .collect::<HashSet<_>>();

        let router_dht = floodfill.then(|| {
            Dht::new(
                local_router_id.clone(),
                profile_storage
                    .get_router_ids(Bucket::Any, |_, info, _| !info.is_floodfill())
                    .into_iter()
                    .collect::<HashSet<_>>(),
                metrics.clone(),
            )
        });

        metrics.counter(NUM_FLOODFILLS).increment(floodfills.len());

        tracing::info!(
            target: LOG_TARGET,
            num_floodfills = ?floodfills.len(),
            ?floodfill,
            "starting netdb",
        );

        let (handle_tx, handle_rx) = mpsc::with_recycle(64, NetDbActionRecycle::default());

        (
            Self {
                active: HashMap::new(),
                floodfill_dht: Dht::new(
                    local_router_id.clone(),
                    floodfills.clone(),
                    metrics.clone(),
                ),
                router_dht,
                exploratory_pool_handle,
                floodfill,
                routers: HashMap::new(),
                handle_rx,
                inbound_tunnels: TunnelSelector::new(),
                lease_sets: HashMap::new(),
                local_router_id: local_router_id.clone(),
                maintenance_timer: Box::pin(R::delay(Duration::from_secs(5))),
                metrics,
                netdb_msg_rx,
                net_id,
                outbound_tunnels: TunnelSelector::new(),
                query_timers: R::join_set(),
                router_info_publishers: RouterInfoPublisher::new(
                    local_router_id,
                    local_router_info,
                ),
                router_infos: HashMap::new(),
                profile_storage,
                service,
            },
            NetDbHandle::new(handle_tx),
        )
    }

    /// Collect `NetDb`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Handle established connection to `router`.
    fn on_connection_established(&mut self, router_id: RouterId) {
        let is_floodfill = self.profile_storage.is_floodfill(&router_id);

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            ?is_floodfill,
            "connection established",
        );

        // send any pending messages to the connected router
        //
        // if the message was of the expiring kind (flooding) and the payload inside the i2np
        // message has expired, the message is skipped
        if let Some(RouterState::Dialing { pending_messages }) = self.routers.remove(&router_id) {
            let now = R::time_since_epoch();

            tracing::trace!(
                target: LOG_TARGET,
                floodfill = %router_id,
                num_pending = ?pending_messages.len(),
                "router with pending messages connected",
            );

            pending_messages.into_iter().for_each(|message| {
                let message = match message {
                    MessageKind::NonExpiring { message } => Some(message),
                    MessageKind::Expiring { message, expires } if expires > now => Some(message),
                    MessageKind::Expiring { expires, .. } => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?expires,
                            "message has expired, will not send",
                        );
                        None
                    }
                };

                if let Some(message) = message {
                    if let Err(error) = self.service.send(&router_id, message) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            ?error,
                            "failed to send message",
                        );
                    }
                }
            });
        }

        if is_floodfill {
            self.floodfill_dht.add_router(router_id.clone());
            self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
        } else {
            self.router_dht.as_mut().map(|dht| dht.add_router(router_id.clone()));
        }

        self.routers.insert(router_id, RouterState::Connected);
    }

    /// Handle closed connection to `router`.
    fn on_connection_closed(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            None => tracing::trace!(
                target: LOG_TARGET,
                %router_id,
                "connection closed",
            ),
            Some(_) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    "connection closed",
                );
                self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).decrement(1);
            }
        }
    }

    // Handle connection failure to `router_id`.
    fn on_connection_failure(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            Some(RouterState::Dialing { pending_messages }) => tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                num_pending_messages = ?pending_messages.len(),
                "failed to establish connection",
            ),
            _ => tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "failed to establish connection",
            ),
        }
    }

    /// Flood `message` to `routers`.
    fn send_message(&mut self, routers: &[RouterId], message: MessageKind) {
        routers.iter().for_each(|router_id| match self.routers.get_mut(router_id) {
            None => match self.service.connect(router_id) {
                Err(error) => tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    ?error,
                    "failed to connect to router",
                ),
                Ok(()) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        "starting to dial router",
                    );

                    self.routers.insert(
                        router_id.clone(),
                        RouterState::Dialing {
                            pending_messages: vec![message.clone()],
                        },
                    );
                }
            },
            Some(RouterState::Dialing { pending_messages }) => {
                pending_messages.push(message.clone());
            }
            Some(RouterState::Connected) => {
                if let Err(error) = self.service.send(router_id, message.clone().into_inner()) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send message to router",
                    );
                }
            }
        });
    }

    /// Handle [`DatabaseStore`] for [`RouterInfo`] if the local router is run as a floodfill.
    fn on_router_info_store(
        &mut self,
        key: Bytes,
        reply: StoreReplyType,
        message: &[u8],
        router_info: RouterInfo,
    ) {
        let router_id = router_info.identity.id();

        if router_info.net_id() != self.net_id {
            tracing::warn!(
                target: LOG_TARGET,
                local_net_id = ?self.net_id,
                remote_net_id = ?router_info.net_id(),
                "invalid network id, ignoring router info store",
            );
            return;
        }

        if router_id == self.local_router_id {
            tracing::warn!(
                target: LOG_TARGET,
                "local router id, ignoring router info store",
            );
            return;
        }

        tracing::trace!(
            target: LOG_TARGET,
            %router_id,
            "router info store",
        );
        let expires =
            Duration::from_millis(*router_info.published.date()) + Duration::from_secs(60 * 60);

        if expires < R::time_since_epoch() {
            tracing::debug!(
                target: LOG_TARGET,
                ?expires,
                "stale router info, ignoring",
            );
            return;
        }

        // parse the router info set from the database store, store it in the set of router infos we
        // keep track of and flood it to three floodfills closest to `key`
        let raw_router_info = DatabaseStore::<R>::extract_raw_router_info(message);
        self.router_infos.insert(
            key.clone(),
            (
                raw_router_info.clone(),
                Duration::from_millis(*router_info.published.date()),
            ),
        );
        if router_info.is_floodfill() {
            self.floodfill_dht.add_router(router_id.clone());
        }
        self.profile_storage.add_router(router_info);
        self.router_dht.as_mut().map(|dht| dht.add_router(router_id.clone()));

        match reply {
            StoreReplyType::None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "reply type is `None`, don't flood the router info",
                );
                return;
            }
            StoreReplyType::Tunnel {
                reply_token,
                tunnel_id,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::standard()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &TunnelGateway {
                            tunnel_id,
                            payload: &message,
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
            StoreReplyType::Router {
                reply_token,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
        }

        let floodfills = self.floodfill_dht.closest(&key, 3usize).collect::<Vec<_>>();
        if floodfills.is_empty() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "cannot flood router info, no floodfills",
            );
            return;
        }

        let message = DatabaseStoreBuilder::new(
            key,
            DatabaseStoreKind::RouterInfo {
                router_info: raw_router_info,
            },
        )
        .build();

        let message_id = R::rng().next_u32();
        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseStore)
            .with_message_id(message_id)
            .with_payload(&message)
            .build();

        self.send_message(&floodfills, MessageKind::Expiring { message, expires });
    }

    /// Handle [`DatabaseStore`] for [`LeasetSet2`] if the local router is run as a floodfill.
    fn on_lease_set_store(
        &mut self,
        key: Bytes,
        reply: StoreReplyType,
        message: &[u8],
        lease_set: LeaseSet2,
    ) {
        let destination_id = lease_set.header.destination.id();

        tracing::trace!(
            target: LOG_TARGET,
            %destination_id,
            "lease set store",
        );

        if lease_set.is_expired::<R>() {
            tracing::warn!(
                target: LOG_TARGET,
                %destination_id,
                expired = ?lease_set.header.expires,
                "received an expired lease set, ignoring",
            );
            return;
        }

        // parse the raw lease set from the database store, store it in the set of leases we keep
        // track of and flood it to three floodfills closest to `key`
        let raw_lease_set = DatabaseStore::<R>::extract_raw_lease_set(message);
        let expires = lease_set.expires();

        self.lease_sets.insert(key.clone(), (raw_lease_set.clone(), expires));

        match reply {
            StoreReplyType::None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "reply type is `None`, don't flood the router info",
                );
                return;
            }
            StoreReplyType::Tunnel {
                reply_token,
                tunnel_id,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::standard()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &TunnelGateway {
                            tunnel_id,
                            payload: &message,
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
            StoreReplyType::Router {
                reply_token,
                router_id,
            } => {
                let expires = R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION;

                let message = MessageBuilder::short()
                    .with_expiration(expires)
                    .with_message_type(MessageType::DeliveryStatus)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(
                        &DeliveryStatus {
                            message_id: reply_token,
                            timestamp: R::time_since_epoch(),
                        }
                        .serialize(),
                    )
                    .build();

                self.send_message(&[router_id], MessageKind::Expiring { message, expires });
            }
        }

        let floodfills = self.floodfill_dht.closest(&key, 3usize).collect::<Vec<_>>();
        if floodfills.is_empty() {
            tracing::debug!(
                target: LOG_TARGET,
                %destination_id,
                "cannot flood lease set, no floodfills",
            );
            return;
        }

        let message = DatabaseStoreBuilder::new(
            key,
            DatabaseStoreKind::LeaseSet2 {
                lease_set: raw_lease_set,
            },
        )
        .build();

        let message_id = R::rng().next_u32();
        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseStore)
            .with_message_id(message_id)
            .with_payload(&message)
            .build();

        self.send_message(&floodfills, MessageKind::Expiring { message, expires });
    }

    /// Handle [`DatabaseLookup`] for a [`LeaseSet2`].
    ///
    /// If lease set under `key` is not found in local storage, a [`DatabaseSearchReply`] message
    /// with floodfills closest to `key`, ignoring floodfills listed in `ignore`, is sent the sender
    /// either directly or via an exploratory tunnel.
    fn on_lease_set_lookup(
        &mut self,
        key: Bytes,
        reply_type: ReplyType,
        ignore: HashSet<RouterId>,
    ) {
        let (message_type, message) = match self.lease_sets.get(&key) {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "lease set not found from local storage",
                );

                // get floodfills closest to `key`, ignoring floodfills listed in `ignore`
                //
                // the reply list is limited to 16 floodfills
                let routers = self
                    .floodfill_dht
                    .closest_with_ignore(&key, SEARCH_REPLY_NUM_ROUTERS, &ignore)
                    .collect::<Vec<_>>();

                (
                    MessageType::DatabaseSearchReply,
                    DatabaseSearchReply {
                        from: self.local_router_id.to_vec(),
                        key,
                        routers,
                    }
                    .serialize(),
                )
            }
            Some((lease_set, _)) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "lease set found from local storage",
                );

                (
                    MessageType::DatabaseStore,
                    DatabaseStoreBuilder::new(
                        key,
                        DatabaseStoreKind::LeaseSet2 {
                            lease_set: lease_set.clone(),
                        },
                    )
                    .build(),
                )
            }
        };

        match reply_type {
            ReplyType::Tunnel {
                tunnel_id,
                router_id,
            } => {
                let message = MessageBuilder::standard()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err(error) = self.exploratory_pool_handle.sender().try_send_to_tunnel(
                    router_id.clone(),
                    tunnel_id,
                    message,
                ) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        %tunnel_id,
                        ?error,
                        "failed to send database lookup reply to tunnel",
                    );
                }
            }
            ReplyType::Router { router_id } => {
                let message = MessageBuilder::short()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err(error) = self.service.send(&router_id, message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send database lookup reply to router",
                    );
                }
            }
        }
    }

    /// Handle [`DatabaseLookup`] for a [`RouterInfo`].
    ///
    /// If router info under `key` is not found in local storage, a [`DatabaseSearchReply`] message
    /// with floodfills closest to `key`, ignoring floodfills listed in `ignore`, is sent the sender
    /// either directly or via an exploratory tunnel.
    fn on_router_info_lookup(
        &mut self,
        key: Bytes,
        reply_type: ReplyType,
        ignore: HashSet<RouterId>,
    ) {
        let (message_type, message) = match self.router_infos.get(&key) {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "router info not found from local storage",
                );

                // get floodfills closest to `key`, ignoring floodfills listed in `ignore`
                //
                // the reply list is limited to 16 floodfills
                let routers = self
                    .floodfill_dht
                    .closest_with_ignore(&key, SEARCH_REPLY_NUM_ROUTERS, &ignore)
                    .collect::<Vec<_>>();

                (
                    MessageType::DatabaseSearchReply,
                    DatabaseSearchReply {
                        from: self.local_router_id.to_vec(),
                        key,
                        routers,
                    }
                    .serialize(),
                )
            }
            Some((router_info, _)) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    key = ?key[..4],
                    "router info found from local storage",
                );

                (
                    MessageType::DatabaseStore,
                    DatabaseStoreBuilder::new(
                        key,
                        DatabaseStoreKind::RouterInfo {
                            router_info: router_info.clone(),
                        },
                    )
                    .build(),
                )
            }
        };

        match reply_type {
            ReplyType::Tunnel {
                tunnel_id,
                router_id,
            } => {
                let message = MessageBuilder::standard()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err(error) = self.exploratory_pool_handle.sender().try_send_to_tunnel(
                    router_id.clone(),
                    tunnel_id,
                    message,
                ) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        %tunnel_id,
                        ?error,
                        "failed to send database lookup reply to tunnel",
                    );
                }
            }
            ReplyType::Router { router_id } => {
                let message = MessageBuilder::short()
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_message_type(message_type)
                    .with_message_id(R::rng().next_u32())
                    .with_payload(&message)
                    .build();

                if let Err(error) = self.service.send(&router_id, message) {
                    tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        ?error,
                        "failed to send database lookup reply to router",
                    );
                }
            }
        }
    }

    /// Handle router exploration lookup.
    fn on_router_exploration(
        &mut self,
        key: Bytes,
        reply_type: ReplyType,
        ignore: HashSet<RouterId>,
    ) {
        let Some(dht) = self.router_dht.as_mut() else {
            tracing::warn!(
                target: LOG_TARGET,
                "ignore router exploration, not a floodfill",
            );
            return;
        };

        let routers = dht
            .closest_with_ignore(&key, SEARCH_REPLY_NUM_ROUTERS, &ignore)
            .collect::<Vec<_>>();

        tracing::trace!(
            target: LOG_TARGET,
            num_routers = ?routers.len(),
            "send router exploration reply",
        );

        let message = Message {
            message_type: MessageType::DatabaseSearchReply,
            message_id: R::rng().next_u32(),
            expiration: R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: DatabaseSearchReply {
                from: self.local_router_id.to_vec(),
                key: key.clone(),
                routers,
            }
            .serialize()
            .to_vec(),
        };

        let (router_id, message) = match reply_type {
            ReplyType::Tunnel {
                tunnel_id,
                router_id,
            } => (
                router_id,
                MessageBuilder::short()
                    .with_message_type(MessageType::TunnelGateway)
                    .with_message_id(R::rng().next_u32())
                    .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                    .with_payload(
                        &TunnelGateway {
                            tunnel_id,
                            payload: &message.serialize_standard(),
                        }
                        .serialize(),
                    )
                    .build(),
            ),
            ReplyType::Router { router_id } => (router_id, message.serialize_short()),
        };

        self.send_message(&[router_id], MessageKind::NonExpiring { message });
    }

    /// Handle I2NP message.
    fn on_message(&mut self, message: Message) -> crate::Result<()> {
        self.metrics.counter(NUM_NETDB_MESSAGES).increment(1);

        match message.message_type {
            MessageType::DatabaseStore => {
                let DatabaseStore {
                    key,
                    payload,
                    reply,
                    ..
                } = DatabaseStore::<R>::parse(&message.payload).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "malformed database store received",
                    );
                    Error::InvalidData
                })?;

                match self.active.remove(&key) {
                    None => match payload {
                        DatabaseStorePayload::RouterInfo { router_info } if self.floodfill => {
                            self.on_router_info_store(key, reply, &message.payload, router_info);
                        }
                        DatabaseStorePayload::LeaseSet2 { lease_set } if self.floodfill => {
                            self.on_lease_set_store(key, reply, &message.payload, lease_set);
                        }
                        DatabaseStorePayload::RouterInfo { router_info } => tracing::trace!(
                            target: LOG_TARGET,
                            router_id = %router_info.identity.id(),
                            "ignoring router info database store",
                        ),
                        DatabaseStorePayload::LeaseSet2 { lease_set } => tracing::warn!(
                            target: LOG_TARGET,
                            destination_id = %lease_set.header.destination.id(),
                            "ignoring lease set database store",
                        ),
                    },
                    Some(kind) => match (payload, kind) {
                        (
                            DatabaseStorePayload::LeaseSet2 { lease_set },
                            QueryKind::Leaseset { tx },
                        ) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                destination_id = %lease_set.header.destination.id(),
                                "lease set query reply received",
                            );

                            let _ = tx.send(Ok(lease_set));
                        }
                        (DatabaseStorePayload::RouterInfo { router_info }, QueryKind::Router) => {
                            let router_id = router_info.identity.id();

                            tracing::trace!(
                                target: LOG_TARGET,
                                %router_id,
                                "router info query reply received",
                            );

                            if router_info.net_id() != self.net_id {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    local_net_id = ?self.net_id,
                                    remote_net_id = ?router_info.net_id(),
                                    "invalid network id, ignoring router info query reply",
                                );
                                return Ok(());
                            }

                            if router_id == self.local_router_id {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    "local router id, ignoring router info query reply",
                                );
                                return Ok(());
                            }

                            if router_info.is_floodfill() {
                                self.floodfill_dht.add_router(router_id.clone());
                            }
                            self.profile_storage.add_router(router_info);
                            self.router_dht.as_mut().map(|dht| dht.add_router(router_id));
                        }
                        (payload, query) => tracing::warn!(
                            target: LOG_TARGET,
                            %payload,
                            ?query,
                            "unhandled database store kind",
                        ),
                    },
                }
            }
            MessageType::DatabaseLookup if self.floodfill => {
                self.metrics.counter(NUM_QUERIES).increment(1);

                let DatabaseLookup {
                    ignore,
                    key,
                    lookup,
                    reply,
                } = DatabaseLookup::parse(&message.payload).ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "malformed database lookup received",
                    );
                    Error::InvalidData
                })?;

                match lookup {
                    LookupType::Leaseset => self.on_lease_set_lookup(key, reply, ignore),
                    LookupType::Router => self.on_router_info_lookup(key, reply, ignore),
                    LookupType::Exploration => self.on_router_exploration(key, reply, ignore),
                    kind => tracing::warn!(
                        target: LOG_TARGET,
                        ?kind,
                        "unsupported lookup kind",
                    ),
                }
            }
            MessageType::DatabaseLookup => tracing::debug!(
                target: LOG_TARGET,
                "ignoring database lookup, not a floodfill",
            ),
            MessageType::DatabaseSearchReply => {
                let DatabaseSearchReply { key, routers, from } =
                    DatabaseSearchReply::parse(&message.payload).ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "malformed database search reply",
                        );
                        Error::InvalidData
                    })?;
                let router_id = RouterId::from(from);

                match self.active.remove(&key) {
                    None => {}
                    Some(QueryKind::Exploration) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            num_routers = ?routers.len(),
                            "router exploration succeeded, send database lookups",
                        );
                    }
                    Some(QueryKind::Leaseset { tx }) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            key = ?base32_encode(key),
                            "lease set lookup failed",
                        );

                        let _ = tx.send(Err(QueryError::ValueNotFound));
                    }
                    Some(QueryKind::Router) => tracing::debug!(
                        target: LOG_TARGET,
                        %router_id,
                        key = ?base64_encode(key),
                        "router info lookup failed",
                    ),
                }

                // filter out routers we already know about and send database lookup queries
                // for the rest of routers
                routers
                    .into_iter()
                    .filter(|router_id| {
                        self.profile_storage.get(router_id).is_none()
                            && router_id != &self.local_router_id
                    })
                    .map(|router_id| {
                        (
                            Bytes::from(router_id.to_vec()),
                            MessageBuilder::short()
                                .with_message_type(MessageType::DatabaseLookup)
                                .with_message_id(R::rng().next_u32())
                                .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                                .with_payload(
                                    &DatabaseLookupBuilder::new(
                                        Bytes::from(router_id.to_vec()),
                                        LookupType::Router,
                                    )
                                    .with_reply_type(ReplyType::Router {
                                        router_id: self.local_router_id.clone(),
                                    })
                                    .build(),
                                )
                                .build(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .for_each(|(key, message)| {
                        self.active.insert(key.clone(), QueryKind::Router);
                        self.query_timers.push(async move {
                            R::delay(QUERY_TIMEOUT).await;
                            key
                        });
                        self.send_message(
                            &[router_id.clone()],
                            MessageKind::NonExpiring { message },
                        );
                    });
            }
            MessageType::DeliveryStatus => {}
            message_type => tracing::warn!(
                target: LOG_TARGET,
                ?message_type,
                "unsupported message",
            ),
        }

        Ok(())
    }

    /// Query `LeaseSet2` under `key` from `NetDb` and return result to caller via `tx`
    fn on_query_lease_set(
        &mut self,
        key: Bytes,
        tx: oneshot::Sender<Result<LeaseSet2, QueryError>>,
    ) {
        let floodfills = self.floodfill_dht.closest(&key, 5usize).collect::<Vec<_>>();

        tracing::debug!(
            target: LOG_TARGET,
            key = ?base32_encode(&key),
            num_floodfills = ?floodfills.len(),
            "query lease set",
        );

        let Some(Lease {
            router_id,
            tunnel_id,
            ..
        }) = self.inbound_tunnels.next_tunnel()
        else {
            tracing::warn!(
                target: LOG_TARGET,
                key = ?base32_encode(&key),
                "cannot send lease set query, no inbound tunnel available",
            );
            debug_assert!(false);

            let _ = tx.send(Err(QueryError::NoTunnel));
            return;
        };

        let Some(outbound_tunnel) = self.outbound_tunnels.next_tunnel() else {
            tracing::warn!(
                target: LOG_TARGET,
                key = ?base32_encode(&key),
                "cannot send lease set query, no outbound tunnel available",
            );
            debug_assert!(false);

            let _ = tx.send(Err(QueryError::NoTunnel));
            return;
        };

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Leaseset)
            .with_reply_type(ReplyType::Tunnel {
                tunnel_id,
                router_id,
            })
            .build();

        let message_id = R::rng().next_u32();
        let message = MessageBuilder::standard()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(message_id)
            .with_payload(&message)
            .build();

        if floodfills.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                "cannot query leaseset, no floodfills",
            );

            let _ = tx.send(Err(QueryError::NoFloodfills));
            return;
        }

        match self.exploratory_pool_handle.sender().try_send_to_router(
            outbound_tunnel,
            floodfills[0].clone(),
            message,
        ) {
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to send query",
                );

                // TODO: correct error, retry later
                let _ = tx.send(Err(QueryError::Timeout));
            }
            Ok(()) => {
                // store leaseset query into active queries and start timer for the query
                self.active.insert(key.clone(), QueryKind::Leaseset { tx });
                self.query_timers.push(async move {
                    R::delay(QUERY_TIMEOUT).await;
                    key
                });
            }
        }
    }

    /// Get `RouterId`'s of the floodfills closest to `key`.
    fn on_get_closest_floodfills(
        &mut self,
        key: Bytes,
        tx: oneshot::Sender<Vec<(RouterId, StaticPublicKey)>>,
    ) {
        let floodfills = self
            .floodfill_dht
            .closest(&key, 3usize)
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|router_id| {
                self.profile_storage
                    .get(&router_id)
                    .map(|router_info| (router_id, router_info.identity.static_key().clone()))
            })
            .collect::<Vec<_>>();

        if floodfills.is_empty() {
            tracing::warn!(
                target: LOG_TARGET,
                key = ?base32_encode(&key),
                "no floodfills available",
            );

            return drop(tx);
        }

        let _ = tx.send(floodfills);
    }

    /// Perform general maintenance of [`NetDb`].
    fn maintain_netdb(&mut self) {
        // prune expired lease sets
        {
            let now = R::time_since_epoch();
            let num_pruned = self
                .lease_sets
                .iter()
                .filter_map(|(key, (_, expires))| (expires < &now).then_some(key.clone()))
                .collect::<Vec<_>>()
                .into_iter()
                .fold(0usize, |count, key| {
                    self.lease_sets.remove(&key);
                    count + 1
                });

            if num_pruned > 0 {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?num_pruned,
                    "pruned expired lease sets",
                );
            }
        }

        // don't do exploration if the router is run as a floodfill router
        if self.floodfill {
            return;
        }

        let key = {
            let mut key = BytesMut::zeroed(32);
            R::rng().fill_bytes(&mut key);

            key.freeze()
        };

        let floodfills = self.floodfill_dht.closest(&key, 1usize).collect::<Vec<_>>();
        let Some(floodfill) = floodfills.first() else {
            tracing::warn!(
                target: LOG_TARGET,
                "cannot perform router exploration, not enough floodfills",
            );
            return;
        };

        tracing::trace!(
            target: LOG_TARGET,
            %floodfill,
            "send router exploration query",
        );

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Exploration)
            .with_reply_type(ReplyType::Router {
                router_id: self.local_router_id.clone(),
            })
            .build();

        let message = MessageBuilder::short()
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_type(MessageType::DatabaseLookup)
            .with_message_id(R::rng().next_u32())
            .with_payload(&message)
            .build();

        self.active.insert(key.clone(), QueryKind::Exploration);
        self.query_timers.push(async move {
            R::delay(QUERY_TIMEOUT).await;
            key
        });
        self.send_message(&[floodfill.clone()], MessageKind::NonExpiring { message });
    }
}

impl<R: Runtime> Future for NetDb<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|message| {
                        if let Err(error) = self.on_message(message) {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                "failed to handle message",
                            );
                        }
                    }),
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionFailure { router })) =>
                    self.on_connection_failure(router),
                Poll::Ready(Some(SubsystemEvent::Dummy)) => {}
            }
        }

        loop {
            match self.netdb_msg_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(message)) =>
                    if let Err(error) = self.on_message(message) {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to handle message",
                        );
                    },
            }
        }

        // events from the exploratory pool are not interesting to `NetDb`
        loop {
            match self.exploratory_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                    self.outbound_tunnels.add_tunnel(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                    self.outbound_tunnels.remove_tunnel(|tunnel| tunnel != &tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { lease, .. })) => {
                    self.inbound_tunnels.add_tunnel(lease);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                    self.inbound_tunnels.remove_tunnel(|lease| lease.tunnel_id != tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::Message { message })) => {
                    let _ = self.on_message(message);
                }
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) => return Poll::Ready(()),
                Poll::Ready(Some(_)) => {}
            }
        }

        loop {
            match self.handle_rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(NetDbAction::QueryLeaseSet2 { key, tx })) =>
                    self.on_query_lease_set(key, tx),
                Poll::Ready(Some(NetDbAction::GetClosestFloodfills { key, tx })) =>
                    self.on_get_closest_floodfills(key, tx),
                Poll::Ready(Some(NetDbAction::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.query_timers.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(key)) =>
                    if let Some(kind) = self.active.remove(&key) {
                        match kind {
                            QueryKind::Leaseset { tx } => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    key = %base32_encode(&key),
                                    "leaseset query timed out",
                                );

                                let _ = tx.send(Err(QueryError::Timeout));
                            }
                            kind => tracing::debug!(
                                target: LOG_TARGET,
                                ?kind,
                                "query timed out",
                            ),
                        }
                    },
            }
        }

        if self.maintenance_timer.poll_unpin(cx).is_ready() {
            self.maintain_netdb();

            // reset timer and register it into the executor
            self.maintenance_timer = Box::pin(R::delay(NETDB_MAINTENANCE_INTERVAL));
            let _ = self.maintenance_timer.poll_unpin(cx);
        }

        if self.router_info_publishers.poll_unpin(cx).is_ready() {
            let key = Bytes::from(self.local_router_id.to_vec());

            match self.floodfill_dht.closest(key, 1usize).collect::<Vec<_>>().pop() {
                None => tracing::warn!(
                    target: LOG_TARGET,
                    "unable to publish router info, no floodfills",
                ),
                Some(floodfill) => {
                    let (reply_token, message) = self.router_info_publishers.publish();

                    tracing::trace!(
                        target: LOG_TARGET,
                        %floodfill,
                        %reply_token,
                        "publish local router info",
                    );

                    self.send_message(&[floodfill], MessageKind::NonExpiring { message });
                }
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{SigningPrivateKey, StaticPrivateKey},
        primitives::{
            Capabilities, Date, Destination, DestinationId, LeaseSet2Header, RouterAddress,
            RouterIdentity, RouterInfo, Str, TransportKind,
        },
        runtime::mock::MockRuntime,
        subsystem::{InnerSubsystemEvent, SubsystemCommand},
        transport::ProtocolCommand,
        tunnel::TunnelMessage,
    };
    use thingbuf::mpsc::channel;

    #[tokio::test]
    async fn lease_set_store_to_floodfill() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set })
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert_eq!(netdb.lease_sets.len(), 1);
        assert!((0..3).all(|_| match rx.try_recv().unwrap() {
            ProtocolCommand::Connect { router } => {
                assert!(floodfills.remove(&router.identity.id()));
                true
            }
            _ => false,
        }));
        assert_eq!(netdb.routers.len(), 4);
        assert!(netdb
            .routers
            .values()
            .all(|state| std::matches!(state, RouterState::Dialing { .. })));
    }

    #[tokio::test]
    async fn lease_set_store_to_non_floodfill() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            false,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set })
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert!(netdb.lease_sets.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn expired_lease_set_store() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: (MockRuntime::time_since_epoch()
                                - Duration::from_secs(5 * 60))
                            .as_secs() as u32,
                            expires: (Duration::from_secs(60)).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set })
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert!(netdb.lease_sets.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn expired_lease_sets_are_pruned() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key1, expired_lease_set1) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                            expires: Duration::from_secs(10).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let (key2, expired_lease_set2) = {
            let sgk = SigningPrivateKey::from_bytes(&[2u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                            expires: Duration::from_secs(5).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let (key3, valid_lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[3u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: (MockRuntime::time_since_epoch() - Duration::from_secs(60))
                                .as_secs() as u32,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        // store first lease set that is about to expire
        {
            let message = DatabaseStoreBuilder::new(
                key1,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: expired_lease_set1,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

            assert!(netdb.lease_sets.is_empty());
            assert!(netdb
                .on_message(Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                })
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 1);
            assert_eq!(netdb.routers.len(), 4);
            assert!((0..3).all(|_| match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router } => {
                    assert!(floodfills.remove(&router.identity.id()));
                    true
                }
                _ => false,
            }));
            assert!(netdb.routers.values().all(|state| match state {
                RouterState::Dialing { pending_messages } => {
                    assert_eq!(pending_messages.len(), 1);
                    true
                }
                _ => false,
            }));
        }

        // store second expiring lease set and verify floodfills are pending
        {
            let message = DatabaseStoreBuilder::new(
                key2,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: expired_lease_set2,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

            assert_eq!(netdb.lease_sets.len(), 1);
            assert!(netdb
                .on_message(Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                })
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 2);
            assert_eq!(netdb.routers.len(), 5);
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.profile_storage.is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 2);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }

                    true
                }
                _ => false,
            }));
        }

        // store non-expiring lease set and verify floodfills are pending
        {
            let message = DatabaseStoreBuilder::new(
                key3,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: valid_lease_set,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

            assert_eq!(netdb.lease_sets.len(), 2);
            assert!(netdb
                .on_message(Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                })
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 3);
            assert_eq!(netdb.routers.len(), 6);
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.profile_storage.is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 3);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }
                    true
                }
                _ => false,
            }));
        }

        // poll netdb until it does its maintenance
        tokio::time::timeout(Duration::from_secs(35), &mut netdb).await.unwrap_err();

        // verify two of the lease sets are pruned
        assert_eq!(netdb.lease_sets.len(), 1);
    }

    #[tokio::test]
    async fn router_info_store_to_floodfill() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    + Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: HashMap::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let message = DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info })
            .with_reply_type(StoreReplyType::Router {
                reply_token: MockRuntime::rng().next_u32(),
                router_id: RouterId::random(),
            })
            .build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert_eq!(netdb.router_infos.len(), 1);
        assert!((0..3).all(|_| match rx.try_recv().unwrap() {
            ProtocolCommand::Connect { router } => {
                assert!(floodfills.remove(&router.identity.id()));
                true
            }
            _ => false,
        }));
        assert_eq!(netdb.routers.len(), 4);
        assert!(netdb
            .routers
            .values()
            .all(|state| std::matches!(state, RouterState::Dialing { .. })));
    }

    #[tokio::test]
    async fn stale_router_info_not_stored_nor_flooded() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    - Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: HashMap::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info }).build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert!(netdb.router_infos.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn lease_set_query() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, lease_set, expires) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };
            let lease_set = Bytes::from(
                LeaseSet2 {
                    header: LeaseSet2Header {
                        destination,
                        published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                        expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                    },
                    public_keys: vec![sk.public()],
                    leases: vec![lease1.clone(), lease2.clone()],
                }
                .serialize(&sgk),
            );
            let expires = LeaseSet2::parse(&lease_set).unwrap().expires();

            (Bytes::from(id.to_vec()), lease_set, expires)
        };

        netdb.lease_sets.insert(key.clone(), (lease_set, expires));

        let tunnel_id = TunnelId::random();
        let router_id = RouterId::random();

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Leaseset)
            .with_reply_type(ReplyType::Tunnel {
                tunnel_id,
                router_id: router_id.clone(),
            })
            .build();

        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseLookup,
                ..Default::default()
            })
            .is_ok());

        match tm_rx.try_recv().unwrap() {
            TunnelMessage::TunnelDelivery {
                gateway,
                tunnel_id: dst_tunnel_id,
                message,
            } => {
                assert_eq!(gateway, router_id);
                assert_eq!(dst_tunnel_id, tunnel_id);

                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseStore);

                match DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap().payload {
                    DatabaseStorePayload::LeaseSet2 { lease_set } => {
                        assert_eq!(key, Bytes::from(lease_set.header.destination.id().to_vec()));
                    }
                    _ => panic!("invalid payload type"),
                }
            }
            _ => panic!("invalid message"),
        }
    }

    #[tokio::test]
    async fn lease_set_query_value_not_found() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<Vec<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let key = Bytes::from(DestinationId::random().to_vec());
        let tunnel_id = TunnelId::random();
        let router_id = RouterId::random();

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Leaseset)
            .with_reply_type(ReplyType::Tunnel {
                tunnel_id,
                router_id: router_id.clone(),
            })
            .with_ignored_routers(vec![floodfills[0].clone(), floodfills[1].clone()])
            .build();

        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseLookup,
                ..Default::default()
            })
            .is_ok());

        match tm_rx.try_recv().unwrap() {
            TunnelMessage::TunnelDelivery {
                gateway,
                tunnel_id: dst_tunnel_id,
                message,
            } => {
                assert_eq!(gateway, router_id);
                assert_eq!(dst_tunnel_id, tunnel_id);

                let message = Message::parse_standard(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseSearchReply);

                let message = DatabaseSearchReply::parse(&message.payload).unwrap();

                assert_eq!(message.routers.len(), 1);
                assert_eq!(message.routers[0], floodfills[2]);
                assert_eq!(message.from, netdb.local_router_id.to_vec());
                assert_eq!(message.key, key);
            }
            _ => panic!("invalid message"),
        }
    }

    #[tokio::test]
    async fn router_info_query() {
        let (mut service, _rx, tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // register new router into `service`
        let router_id = RouterId::random();
        let (conn_tx, conn_rx) = channel(16);
        tx.send(InnerSubsystemEvent::ConnectionEstablished {
            router: router_id.clone(),
            tx: conn_tx,
        })
        .await
        .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), service.next()).await;

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    - Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: HashMap::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };
        netdb.router_infos.insert(key.clone(), (router_info, Duration::from_secs(10)));

        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Router)
            .with_reply_type(ReplyType::Router {
                router_id: router_id.clone(),
            })
            .build();

        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseLookup,
                ..Default::default()
            })
            .is_ok());

        assert!(tm_rx.try_recv().is_err());

        match conn_rx.try_recv().unwrap() {
            SubsystemCommand::SendMessage { message } => {
                let message = Message::parse_short(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseStore);

                match DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap().payload {
                    DatabaseStorePayload::RouterInfo { router_info } => {
                        assert_eq!(key, Bytes::from(router_info.identity.id().to_vec()));
                    }
                    _ => panic!("invalid payload type"),
                }
            }
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test]
    async fn router_info_query_value_not_found() {
        let (mut service, _rx, tx, storage) = TransportService::new();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // register new router into `service`
        let router_id = RouterId::random();
        let (conn_tx, conn_rx) = channel(16);
        tx.send(InnerSubsystemEvent::ConnectionEstablished {
            router: router_id.clone(),
            tx: conn_tx,
        })
        .await
        .unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(200), service.next()).await;

        // add few floodfills to router storage
        let floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<Vec<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let key = Bytes::from(RouterId::random().to_vec());
        let message = DatabaseLookupBuilder::new(key.clone(), LookupType::Router)
            .with_reply_type(ReplyType::Router {
                router_id: router_id.clone(),
            })
            .with_ignored_routers(vec![floodfills[0].clone(), floodfills[2].clone()])
            .build();

        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseLookup,
                ..Default::default()
            })
            .is_ok());

        assert!(tm_rx.try_recv().is_err());

        match conn_rx.try_recv().unwrap() {
            SubsystemCommand::SendMessage { message } => {
                let message = Message::parse_short(&message).unwrap();
                assert_eq!(message.message_type, MessageType::DatabaseSearchReply);

                let message = DatabaseSearchReply::parse(&message.payload).unwrap();

                assert_eq!(message.routers.len(), 1);
                assert_eq!(message.routers[0], floodfills[1]);
                assert_eq!(message.from, netdb.local_router_id.to_vec());
                assert_eq!(message.key, key);
            }
            _ => panic!("invalid command"),
        }
    }

    #[tokio::test]
    async fn pending_messages_sent_when_floodfill_connects() {
        let (service, _rx, tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            false,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        // set timer to a shorter timeout and poll netdb until it sends a router exploration
        netdb.maintenance_timer = Box::pin(tokio::time::sleep(Duration::from_secs(2)));
        tokio::time::timeout(Duration::from_secs(5), &mut netdb).await.unwrap_err();

        let selected_floofill = netdb
            .routers
            .iter()
            .find(|(_, state)| match state {
                RouterState::Dialing { pending_messages } if pending_messages.len() == 1 => true,
                _ => false,
            })
            .unwrap()
            .0;

        // register the selected floodfill into netdb
        let (conn_tx, conn_rx) = channel(16);
        tx.send(InnerSubsystemEvent::ConnectionEstablished {
            router: selected_floofill.clone(),
            tx: conn_tx,
        })
        .await
        .unwrap();

        let future = async {
            loop {
                tokio::select! {
                    _ = &mut netdb => {}
                    event = conn_rx.recv() => match event.unwrap() {
                        SubsystemCommand::SendMessage { message } => break message,
                        _ => panic!("invalid command"),
                    }
                }
            }
        };

        let message = tokio::time::timeout(Duration::from_secs(2), future).await.unwrap();
        let message = Message::parse_short(&message).unwrap();

        assert_eq!(message.message_type, MessageType::DatabaseLookup);
        assert_eq!(
            DatabaseLookup::parse(&message.payload).unwrap().lookup,
            LookupType::Exploration
        );
    }

    #[tokio::test]
    async fn expired_pending_lease_sets_not_flooded() {
        let (service, rx, tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key1, expired_lease_set1) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: MockRuntime::time_since_epoch().as_secs() as u32,
                            expires: Duration::from_secs(5).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let (key2, valid_lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[2u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: (MockRuntime::time_since_epoch() - Duration::from_secs(60))
                                .as_secs() as u32,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        // store first lease set that is about to expire
        {
            let message = DatabaseStoreBuilder::new(
                key1,
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: expired_lease_set1,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

            assert!(netdb.lease_sets.is_empty());
            assert!(netdb
                .on_message(Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                })
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 1);
            assert_eq!(netdb.routers.len(), 4);
            assert!((0..3).all(|_| match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router } => {
                    assert!(floodfills.remove(&router.identity.id()));
                    true
                }
                _ => false,
            }));
            assert!(netdb.routers.values().all(|state| match state {
                RouterState::Dialing { pending_messages } => {
                    assert_eq!(pending_messages.len(), 1);
                    true
                }
                _ => false,
            }));
        }

        // store second expiring lease set and verify floodfills are pending
        {
            let message = DatabaseStoreBuilder::new(
                key2.clone(),
                DatabaseStoreKind::LeaseSet2 {
                    lease_set: valid_lease_set,
                },
            )
            .with_reply_type(StoreReplyType::Tunnel {
                reply_token: MockRuntime::rng().next_u32(),
                tunnel_id: TunnelId::random(),
                router_id: RouterId::random(),
            })
            .build();

            assert_eq!(netdb.lease_sets.len(), 1);
            assert!(netdb
                .on_message(Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                })
                .is_ok());
            assert_eq!(netdb.lease_sets.len(), 2);
            assert_eq!(netdb.routers.len(), 5);
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.profile_storage.is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 2);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }
                    true
                }
                _ => false,
            }));
        }

        // wait for 10 seconds so the first lease set expires
        tokio::time::sleep(Duration::from_secs(10)).await;

        // register all floodfills to netdb and spawn it int the background
        let channels = floodfills
            .iter()
            .map(|router_id| {
                let (conn_tx, conn_rx) = channel(16);
                tx.try_send(InnerSubsystemEvent::ConnectionEstablished {
                    router: router_id.clone(),
                    tx: conn_tx,
                })
                .unwrap();

                conn_rx
            })
            .collect::<Vec<_>>();
        tokio::spawn(netdb);

        // verify that all floodfillls receive one lease set store, for the still valid lease set
        for channel in channels {
            match tokio::time::timeout(Duration::from_secs(1), channel.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                SubsystemCommand::SendMessage { message } => {
                    let message = Message::parse_short(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::DatabaseStore);

                    let DatabaseStore { key, payload, .. } =
                        DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                    assert_eq!(key, key2);
                    assert!(std::matches!(
                        payload,
                        DatabaseStorePayload::LeaseSet2 { .. }
                    ));
                }
                _ => panic!("invalid event"),
            }

            // verify there are no other messages pending
            match tokio::time::timeout(Duration::from_secs(1), channel.recv()).await {
                Err(_) => {}
                _ => panic!("expected timeout"),
            }
        }
    }

    #[tokio::test]
    async fn expired_pending_router_infos_not_flooded() {
        let (service, rx, tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let mut floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key1, expiring_router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch() + Duration::from_secs(5))
                                    .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: HashMap::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let (key2, valid_router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    + Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: HashMap::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        // store first lease set that is about to expire
        {
            let message = DatabaseStoreBuilder::new(
                key1,
                DatabaseStoreKind::RouterInfo {
                    router_info: expiring_router_info,
                },
            )
            .with_reply_type(StoreReplyType::Router {
                reply_token: MockRuntime::rng().next_u32(),
                router_id: RouterId::random(),
            })
            .build();

            assert!(netdb.lease_sets.is_empty());
            assert!(netdb
                .on_message(Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                })
                .is_ok());
            assert_eq!(netdb.router_infos.len(), 1);
            assert_eq!(netdb.routers.len(), 4);
            assert!((0..3).all(|_| match rx.try_recv().unwrap() {
                ProtocolCommand::Connect { router } => {
                    assert!(floodfills.remove(&router.identity.id()));
                    true
                }
                _ => false,
            }));
            assert!(netdb.routers.values().all(|state| match state {
                RouterState::Dialing { pending_messages } => {
                    assert_eq!(pending_messages.len(), 1);
                    true
                }
                _ => false,
            }));
        }

        // store second expiring lease set and verify floodfills are pending
        {
            let message = DatabaseStoreBuilder::new(
                key2.clone(),
                DatabaseStoreKind::RouterInfo {
                    router_info: valid_router_info,
                },
            )
            .with_reply_type(StoreReplyType::Router {
                reply_token: MockRuntime::rng().next_u32(),
                router_id: RouterId::random(),
            })
            .build();

            assert_eq!(netdb.router_infos.len(), 1);
            assert!(netdb
                .on_message(Message {
                    payload: message.to_vec(),
                    message_type: MessageType::DatabaseStore,
                    ..Default::default()
                })
                .is_ok());
            assert_eq!(netdb.router_infos.len(), 2);
            assert_eq!(netdb.routers.len(), 5);
            assert!(rx.try_recv().is_err());
            assert!(netdb.routers.iter().all(|(router_id, state)| match state {
                RouterState::Dialing { pending_messages } => {
                    if netdb.profile_storage.is_floodfill(router_id) {
                        assert_eq!(pending_messages.len(), 2);
                    } else {
                        assert_eq!(pending_messages.len(), 1);
                    }
                    true
                }
                _ => false,
            }));
        }

        // wait for 10 seconds so the first lease set expires
        tokio::time::sleep(Duration::from_secs(10)).await;

        // register all floodfills to netdb and spawn it int the background
        let channels = floodfills
            .iter()
            .map(|router_id| {
                let (conn_tx, conn_rx) = channel(16);
                tx.try_send(InnerSubsystemEvent::ConnectionEstablished {
                    router: router_id.clone(),
                    tx: conn_tx,
                })
                .unwrap();

                conn_rx
            })
            .collect::<Vec<_>>();
        tokio::spawn(netdb);

        // verify that all floodfillls receive one lease set store, for the still valid lease set
        for channel in channels {
            match tokio::time::timeout(Duration::from_secs(1), channel.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                SubsystemCommand::SendMessage { message } => {
                    let message = Message::parse_short(&message).unwrap();
                    assert_eq!(message.message_type, MessageType::DatabaseStore);

                    let DatabaseStore { key, payload, .. } =
                        DatabaseStore::<MockRuntime>::parse(&message.payload).unwrap();

                    assert_eq!(key, key2);
                    assert!(std::matches!(
                        payload,
                        DatabaseStorePayload::RouterInfo { .. }
                    ));
                }
                _ => panic!("invalid event"),
            }

            // verify there are no other messages pending
            match tokio::time::timeout(Duration::from_secs(1), channel.recv()).await {
                Err(_) => {}
                _ => panic!("expected timeout"),
            }
        }
    }

    #[tokio::test]
    async fn router_info_with_different_network_id_ignored() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch() - Duration::from_secs(60))
                                    .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: HashMap::from_iter([
                                (Str::from("netId"), Str::from("99")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 99,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info }).build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert!(netdb.router_infos.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn lease_set_store_with_zero_reply_token() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, lease_set) = {
            let sgk = SigningPrivateKey::from_bytes(&[1u8; 32]).unwrap();
            let sk = StaticPrivateKey::random(&mut MockRuntime::rng());
            let destination = Destination::new::<MockRuntime>(sgk.public());
            let id = destination.id();

            let lease1 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(80),
            };
            let lease2 = Lease {
                router_id: RouterId::random(),
                tunnel_id: TunnelId::random(),
                expires: MockRuntime::time_since_epoch() + Duration::from_secs(60),
            };

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    LeaseSet2 {
                        header: LeaseSet2Header {
                            destination,
                            published: (MockRuntime::time_since_epoch()).as_secs() as u32,
                            expires: (Duration::from_secs(5 * 60)).as_secs() as u32,
                        },
                        public_keys: vec![sk.public()],
                        leases: vec![lease1.clone(), lease2.clone()],
                    }
                    .serialize(&sgk),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::LeaseSet2 { lease_set }).build();

        assert!(netdb.lease_sets.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert_eq!(netdb.lease_sets.len(), 1);
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn router_info_store_with_zero_reply_token() {
        let (service, rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add few floodfills to router storage
        let _floodfills = (0..3)
            .map(|_| {
                let info = RouterInfo::floodfill::<MockRuntime>();
                let id = info.identity.id();
                storage.add_router(info);

                id
            })
            .collect::<HashSet<_>>();

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        let (key, router_info) = {
            let (identity, _sk, sgk) = RouterIdentity::random();
            let id = identity.id();

            (
                Bytes::from(id.to_vec()),
                Bytes::from(
                    MockRuntime::gzip_compress(
                        RouterInfo {
                            identity,
                            published: Date::new(
                                (MockRuntime::time_since_epoch()
                                    + Duration::from_secs(60 * 60 + 60))
                                .as_millis() as u64,
                            ),
                            addresses: HashMap::from_iter([(
                                TransportKind::Ntcp2,
                                RouterAddress::new_unpublished_ntcp2([1u8; 32], 8888),
                            )]),
                            options: HashMap::from_iter([
                                (Str::from("netId"), Str::from("2")),
                                (Str::from("caps"), Str::from("L")),
                            ]),
                            net_id: 2,
                            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
                        }
                        .serialize(&sgk),
                    )
                    .unwrap(),
                ),
            )
        };

        let message =
            DatabaseStoreBuilder::new(key, DatabaseStoreKind::RouterInfo { router_info }).build();

        assert!(netdb.router_infos.is_empty());
        assert!(netdb
            .on_message(Message {
                payload: message.to_vec(),
                message_type: MessageType::DatabaseStore,
                ..Default::default()
            })
            .is_ok());
        assert_eq!(netdb.router_infos.len(), 1);
        assert!(rx.try_recv().is_err());
        assert!(netdb.routers.is_empty());
    }

    #[tokio::test]
    async fn local_router_info_published() {
        let (service, _rx, _tx, storage) = TransportService::new();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();

        // add floodfill to router storage
        let info = RouterInfo::floodfill::<MockRuntime>();
        let floodfill = info.identity.id();
        storage.add_router(info);

        let (_msg_tx, msg_rx) = channel(64);
        let (mut netdb, _handle) = NetDb::<MockRuntime>::new(
            RouterId::random(),
            true,
            service,
            storage,
            MockRuntime::register_metrics(vec![], None),
            tp_handle,
            2u8,
            msg_rx,
            Bytes::from(vec![1, 2, 3, 4]),
        );

        assert!(std::matches!(netdb.routers.get(&floodfill), None));

        // poll netdb until the initial publish timeout is over
        assert!(tokio::time::timeout(Duration::from_secs(20), &mut netdb).await.is_err());

        match netdb.routers.get(&floodfill).expect("to exist") {
            RouterState::Dialing { pending_messages } => {
                assert_eq!(pending_messages.len(), 1);
            }
            _ => panic!("invalid state"),
        }
    }
}
