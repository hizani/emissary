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
    crypto::StaticPublicKey,
    error::ChannelError,
    i2np::{tunnel::gateway::TunnelGateway, Message},
    primitives::TunnelId,
    router_storage::RouterStorage,
    runtime::{Counter, JoinSet, MetricsHandle, Runtime},
    tunnel::{
        hop::{
            inbound::InboundTunnel, outbound::OutboundTunnel, pending::PendingTunnel, Tunnel,
            TunnelBuildParameters,
        },
        metrics::*,
        new_noise::NoiseContext,
        routing_table::RoutingTable,
    },
    Error,
};

use bytes::Bytes;
use futures::{
    future::{select, BoxFuture, Either},
    FutureExt, Stream, StreamExt,
};
use futures_channel::oneshot;
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(feature = "no_std")]
use spin::rwlock::RwLock;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use super::TunnelPoolConfig;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::pool";

/// Tunnel maintenance interval.
const TUNNEL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);

/// Tunnel build request expiration.
///
/// How long is a pending tunnel kept active before the request is considered failed.
const TUNNEL_BUILD_EXPIRATION: Duration = Duration::from_secs(8);

/// Tunnel channel size.
const TUNNEL_CHANNEL_SIZE: usize = 64usize;

pub trait TunnelSelector: Unpin + Send {
    fn select_outbound_tunnel(&self) -> Option<TunnelId>;
    fn select_inbound_tunnel(&self) -> Option<TunnelId>;
    fn add_outbound_tunnel(&self, tunnel_id: TunnelId);
    fn add_inbound_tunnel(&self, tunnel_id: TunnelId);
    fn remove_outbound_tunnel(&self, tunnel_id: &TunnelId);
    fn remove_inbound_tunnel(&self, tunnel_id: &TunnelId);
}

pub trait HopSelector: Unpin + Send {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>>;
}

/// Tunnel/hop selector for exploratory pool.
///
/// For exploratory inbound tunnel builds, an active outbound tunnel from the same pool is used
/// to deliver the build request. For exploratory outbound tunnel builds, an active inbound
/// tunnel is used to receive the tunnel build reply. If there are no active tunnels, a fake
/// 0-hop inbound/outbound tunnel is used for delivery/reception.
#[derive(Clone)]
pub struct ExploratorySelector {
    /// Active inbound tunnels.
    inbound: Arc<RwLock<HashSet<TunnelId>>>,

    /// Active outbound tunnels.
    outbound: Arc<RwLock<HashSet<TunnelId>>>,

    /// Router storage for selecting hops.
    router_storage: RouterStorage,
}

impl ExploratorySelector {
    /// Create new [`ExploratorySelector`].
    pub fn new(router_storage: RouterStorage) -> Self {
        Self {
            inbound: Default::default(),
            outbound: Default::default(),
            router_storage,
        }
    }

    /// Get reference to [`RouterStorage`].
    pub fn router_storage(&self) -> &RouterStorage {
        &self.router_storage
    }
}

/// Tunnel/hop selector for exploratory pool(s).
///
/// For client inbound tunnel builds, an active outbound tunnel from the same pool is selected
/// for build request delivery. For client outbound tunnel builds, an active inbound tunnel is
/// used for reception of the tunnel build reply. If there are no active inbound/outbound
/// tunnels, a tunnel from the exploratory tunnel pool is selected for reception/delivery. If
/// there are no active tunnels in the exploratory pool, a fake 0-hop tunnel is used instead.
#[derive(Clone)]
pub struct ClientSelector {
    /// Exploratory tunnel selector.
    exploratory: ExploratorySelector,

    /// Active inbound tunnels.
    inbound: Arc<RwLock<HashSet<TunnelId>>>,

    /// Active outbound tunnels.
    outbound: Arc<RwLock<HashSet<TunnelId>>>,
}

impl ClientSelector {
    /// Create new [`ClientSelector`].
    pub fn new(exploratory: ExploratorySelector) -> Self {
        Self {
            exploratory,
            inbound: Default::default(),
            outbound: Default::default(),
        }
    }
}

impl TunnelSelector for ExploratorySelector {
    fn select_outbound_tunnel(&self) -> Option<TunnelId> {
        self.outbound.read().iter().next().copied()
    }

    fn select_inbound_tunnel(&self) -> Option<TunnelId> {
        self.inbound.read().iter().next().copied()
    }

    fn add_outbound_tunnel(&self, tunnel_id: TunnelId) {
        self.outbound.write().insert(tunnel_id);
    }

    fn add_inbound_tunnel(&self, tunnel_id: TunnelId) {
        self.inbound.write().insert(tunnel_id);
    }

    fn remove_outbound_tunnel(&self, tunnel_id: &TunnelId) {
        self.outbound.write().remove(tunnel_id);
    }

    fn remove_inbound_tunnel(&self, tunnel_id: &TunnelId) {
        self.inbound.write().remove(tunnel_id);
    }
}

impl HopSelector for ExploratorySelector {
    fn select_hops(&self, num_hops: usize) -> Option<Vec<(Bytes, StaticPublicKey)>> {
        let routers = self.router_storage.get_routers(num_hops, |_, _| true);

        if routers.len() != num_hops {
            return None;
        }

        Some(
            routers
                .into_iter()
                .map(|info| {
                    (
                        info.identity().hash().clone(),
                        info.identity().static_key().clone(),
                    )
                })
                .collect(),
        )
    }
}

/// Fake 0-hop inbound tunnel.
///
/// These tunnels are used to receive one `TunnelGateway` message which contains a tunnel build
/// response which it routes back to the installed listener (if it exists), after which the tunnel
/// gets destructed.
struct ZeroHopInboundTunnel {
    /// RX channel for receiving a message.
    message_rx: mpsc::Receiver<Message>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel ID.
    tunnel_id: TunnelId,
}

impl ZeroHopInboundTunnel {
    /// Create new [`ZeroHopInboundTunnel`].
    pub fn new(routing_table: RoutingTable, rng: &mut impl RngCore) -> (TunnelId, Self) {
        let (tunnel_id, message_rx) = routing_table.insert_tunnel::<1>(rng);

        (
            tunnel_id,
            Self {
                message_rx,
                routing_table,
                tunnel_id,
            },
        )
    }

    /// Handle receive I2NP message, presumably containing a tunnel build response.
    fn on_message(&self, message: Message) {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            message_type = ?message.message_type,
            "handle message",
        );

        let Some(TunnelGateway { tunnel_id, payload }) = TunnelGateway::parse(&message.payload)
        else {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                message_type = ?message.message_type,
                "invalid message, expected `TunnelGateway`",
            );
            return;
        };

        let Some(message) = Message::parse_standard(&payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                message_type = ?message.message_type,
                "invalid message, expected standard i2np message",
            );
            return;
        };

        self.routing_table.route_message(message);
    }
}

impl Future for ZeroHopInboundTunnel {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match futures::ready!(self.message_rx.poll_recv(cx)) {
            None => {
                tracing::debug!(
                    target: LOG_TARGET,
                    tunnel_id = %self.tunnel_id,
                    "channel closed while waiting for build response",
                );
                return Poll::Ready(());
            }
            Some(message) => {
                self.on_message(message);
                return Poll::Ready(());
            }
        }
    }
}

/// Tunnel build listener.
struct TunnelBuildListener<R: Runtime, T: Tunnel + 'static> {
    /// Pending tunnels.
    pending: R::JoinSet<(TunnelId, crate::Result<T>)>,
}

impl<R: Runtime, T: Tunnel> TunnelBuildListener<R, T> {
    /// Create new [`TunnelBuildListener`].
    pub fn new() -> Self {
        Self {
            pending: R::join_set(),
        }
    }

    /// Get the number of pending tunnels.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Add pending tunnel into set of tunnels that are being waited.
    pub fn add_pending_tunnel(
        &mut self,
        tunnel: PendingTunnel<T>,
        message_rx: oneshot::Receiver<Message>,
    ) {
        self.pending.push(async move {
            match select(message_rx, Box::pin(R::delay(TUNNEL_BUILD_EXPIRATION))).await {
                Either::Right((_, _)) => (*tunnel.tunnel_id(), Err(Error::Timeout)),
                Either::Left((Err(_), _)) => (
                    *tunnel.tunnel_id(),
                    Err(Error::Channel(ChannelError::Closed)),
                ),
                Either::Left((Ok(message), _)) =>
                    (*tunnel.tunnel_id(), tunnel.try_build_tunnel(message)),
            }
        });
    }
}

impl<R: Runtime, T: Tunnel> Stream for TunnelBuildListener<R, T> {
    type Item = (TunnelId, crate::Result<T>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match futures::ready!(self.pending.poll_next_unpin(cx)) {
            None => return Poll::Ready(None),
            Some(result) => return Poll::Ready(Some(result)),
        }
    }
}

/// Tunnel pool.
///
/// Tunnel pool manages a set of inbound and outbound tunnels for a particular destination.
pub struct TunnelPoolNew<R: Runtime, S: TunnelSelector + HopSelector> {
    /// Tunnel pool configuration.
    config: TunnelPoolConfig,

    /// Active inbound tunnels.
    inbound: HashMap<TunnelId, InboundTunnel>,

    /// Tunnel maintenance timer.
    maintenance_timer: BoxFuture<'static, ()>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Noise context.
    noise: NoiseContext,

    /// Active outbound tunnels.
    outbound: HashMap<TunnelId, OutboundTunnel>,

    /// Pending inbound tunnels.
    pending_inbound: TunnelBuildListener<R, InboundTunnel>,

    /// Tunnel RX channels for pending inbound channels.
    pending_inbound_channels: HashMap<TunnelId, mpsc::Receiver<Message>>,

    /// Pending outbound tunnels.
    pending_outbound: TunnelBuildListener<R, OutboundTunnel>,

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel/hop selector for the tunnel pool.
    selector: S,
}

impl<R: Runtime, S: TunnelSelector + HopSelector> TunnelPoolNew<R, S> {
    /// Create new [`TunnelPool`].
    pub fn new(
        config: TunnelPoolConfig,
        selector: S,
        routing_table: RoutingTable,
        noise: NoiseContext,
        metrics_handle: R::MetricsHandle,
    ) -> Self {
        Self {
            config,
            inbound: HashMap::new(),
            maintenance_timer: Box::pin(R::delay(Duration::from_secs(0))),
            metrics_handle,
            noise,
            outbound: HashMap::new(),
            pending_inbound: TunnelBuildListener::new(),
            pending_inbound_channels: HashMap::new(),
            pending_outbound: TunnelBuildListener::new(),
            routing_table,
            selector,
        }
    }

    /// Maintain the tunnel pool.
    ///
    /// If the number of inbound/outbound is less than desired, build new tunnels.
    ///
    /// Each active tunnel gets tested once every 10 seconds by selecting a pair of random tunnels
    /// and sending a test message to the outbound tunnel and receiving the message back via the
    /// paired inbound tunnels.
    fn maintain_pool(&mut self) {
        let num_inbound_to_build = self.config.num_inbound.saturating_sub(self.inbound.len());
        let num_outbound_to_build = self.config.num_outbound.saturating_sub(self.outbound.len());

        // build one or more outbound tunnels
        //
        // select an inbound tunnel for reply delivery from one of the available inbound tunnels
        // and if none exist, create a fake 0-hop inbound tunnel
        for _ in 0..num_outbound_to_build {
            match self.selector.select_inbound_tunnel() {
                Some(tunnel_id) => todo!(),
                None => {
                    let Some(hops) = self.selector.select_hops(self.config.num_outbound_hops)
                    else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            hops_required = ?self.config.num_outbound_hops,
                            "not enough routers for outbound tunnel build",
                        );
                        continue;
                    };

                    // generate message id for the build request and optimistically insert
                    // a listener tx channel for it in the routing table
                    //
                    // if the building the build request fails, the listener must be removed
                    // from the routing table
                    let (message_id, message_rx) =
                        self.routing_table.insert_listener(&mut R::rng());

                    // create fake 0-hop tunnel for receiving the tunnel build response.
                    let (tunnel_id, zero_hop_tunnel) =
                        ZeroHopInboundTunnel::new(self.routing_table.clone(), &mut R::rng());

                    match PendingTunnel::<OutboundTunnel>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            tunnel_id, // TODO: not the tunnel id of the created tunnel!
                            message_id,
                            noise: self.noise.clone(),
                            our_hash: self.noise.local_router_hash().clone(),
                        },
                    ) {
                        Ok((tunnel, router, message)) => {
                            // spawn the fake 0-hop inbound tunnel in the background
                            //
                            // it will exit after receiving its first message because
                            // the tunnel is used only used for this particular build request
                            R::spawn(zero_hop_tunnel);

                            // add pending tunnel into outbound tunnel build listener
                            // and send tunnel build request to the first hop
                            self.pending_outbound.add_pending_tunnel(tunnel, message_rx);
                            self.routing_table.send_message(router, message);
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?tunnel_id,
                                ?message_id,
                                ?error,
                                "failed to create outbound tunnel",
                            );

                            self.routing_table.remove_tunnel(&tunnel_id);
                            self.routing_table.remove_listener(&message_id);
                            continue;
                        }
                    }
                }
            }
        }

        // build one or more inbound tunnels
        //
        // select an outbound for request delivery from one of the available outbound tunnels
        //
        // select an inbound tunnel for reply delivery from one of the pool's inbound tunnels
        // and if none exist, use a fake 0-hop outbound tunnel
        for _ in 0..num_inbound_to_build {
            match self.selector.select_outbound_tunnel() {
                Some(tunnel_id) => todo!(),
                None => {
                    let Some(hops) = self.selector.select_hops(self.config.num_inbound_hops) else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            hops_required = ?self.config.num_inbound_hops,
                            "not enough routers for inbound tunnel build",
                        );
                        continue;
                    };

                    // generate message id for the build request and optimistically insert
                    // a listener tx channel for it in the routing table
                    //
                    // if the building the build request fails, the listener must be removed
                    // from the routing table
                    let (message_id, message_rx) =
                        self.routing_table.insert_listener(&mut R::rng());

                    // generate tunnel id for the inbound tunnel that's about to be built
                    let (tunnel_id, tunnel_rx) =
                        self.routing_table.insert_tunnel::<TUNNEL_CHANNEL_SIZE>(&mut R::rng());

                    match PendingTunnel::<InboundTunnel>::create_tunnel::<R>(
                        TunnelBuildParameters {
                            hops,
                            tunnel_id,
                            message_id,
                            noise: self.noise.clone(),
                            our_hash: self.noise.local_router_hash().clone(),
                        },
                    ) {
                        Ok((tunnel, router, message)) => {
                            // add pending tunnel into outbound tunnel build listener and send
                            // tunnel build request to the first hop
                            //
                            // rx channel for the pending inbound tunnel is saved into
                            // `pending_inbound_channels` from which it will be fetched after the
                            // tunnel build result is received
                            self.pending_inbound_channels.insert(tunnel_id, tunnel_rx);
                            self.pending_inbound.add_pending_tunnel(tunnel, message_rx);
                            self.routing_table.send_message(router, message);
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                ?tunnel_id,
                                ?message_id,
                                ?error,
                                "failed to create outbound tunnel",
                            );

                            self.routing_table.remove_tunnel(&tunnel_id);
                            self.routing_table.remove_listener(&message_id);
                            continue;
                        }
                    }
                }
            }
        }
    }
}

impl<R: Runtime, S: TunnelSelector + HopSelector> Future for TunnelPoolNew<R, S> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(Some((tunnel_id, event))) = self.pending_outbound.poll_next_unpin(cx)
        {
            match event {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to build outbound channel",
                    );

                    self.metrics_handle.counter(NUM_BUILD_FAILURES).increment(1);
                    self.routing_table.remove_tunnel(&tunnel_id);
                }
                Ok(tunnel) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        tunnel_id = %tunnel.tunnel_id(),
                        "outbound tunnel built",
                    );

                    self.outbound.insert(*tunnel.tunnel_id(), tunnel);
                }
            }
        }

        while let Poll::Ready(Some((tunnel_id, event))) = self.pending_inbound.poll_next_unpin(cx) {
            match event {
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to build inbound channel",
                    );

                    self.metrics_handle.counter(NUM_BUILD_FAILURES).increment(1);
                    self.routing_table.remove_tunnel(&tunnel_id);
                    self.pending_inbound_channels.remove(&tunnel_id);
                }
                Ok(tunnel) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        tunnel_id = %tunnel.tunnel_id(),
                        "inbound tunnel built",
                    );

                    // TODO: do something with channel
                    let _ = self.pending_inbound_channels.remove(&tunnel_id);
                    self.inbound.insert(*tunnel.tunnel_id(), tunnel);
                }
            }
        }

        futures::ready!(self.maintenance_timer.poll_unpin(cx));

        // create new timer and register it into the executor
        {
            self.maintenance_timer = Box::pin(R::delay(TUNNEL_MAINTENANCE_INTERVAL));
            let _ = self.maintenance_timer.poll_unpin(cx);
        }

        self.maintain_pool();

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{base64_encode, StaticPrivateKey},
        primitives::{RouterId, RouterInfo},
        runtime::mock::MockRuntime,
        tunnel::tests::TestTransitTunnelManager,
    };
    use futures::StreamExt;
    use tracing_subscriber::prelude::*;

    #[tokio::test]
    async fn build_outbound_exploratory_tunnel() {
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).try_init();

        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);

        let mut tunnel_pool = TunnelPoolNew::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone()),
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // route tunnel build response to the fake 0-hop inbound tunnel
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message);

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.outbound.len(), 1);
        assert_eq!(tunnel_pool.pending_outbound.len(), 0);
    }

    #[tokio::test]
    async fn outbound_exploratory_build_request_expires() {
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).try_init();

        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 0usize,
            num_inbound_hops: 0usize,
            num_outbound: 1usize,
            num_outbound_hops: 3usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);

        let mut tunnel_pool = TunnelPoolNew::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone()),
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_outbound.len(), 1);

        // 1st outbound hop (participant)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (obep)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(TUNNEL_BUILD_EXPIRATION, &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.outbound.len(), 0);
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1))
    }

    #[tokio::test]
    async fn build_inbound_exploratory_tunnel() {
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).try_init();

        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);

        let mut tunnel_pool = TunnelPoolNew::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone()),
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_inbound_channels.len(), 1);

        // 1st outbound hop (ibgw)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // route tunnel build response to the tunnel build response listener
        let message = Message::parse_short(&message).unwrap();
        routing_table.route_message(message);

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_inbound.len(), 0);
        assert!(tunnel_pool.pending_inbound_channels.is_empty());
    }

    #[tokio::test]
    async fn inbound_exploratory_build_request_expires() {
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer()).try_init();

        // create 10 routers and add them to local `RouterStorage`
        let mut routers = (0..10)
            .map(|_| {
                let transit = TestTransitTunnelManager::new();
                let router_id = transit.router();

                (transit.router(), transit)
            })
            .collect::<HashMap<_, _>>();
        let router_storage = RouterStorage::from_random(
            routers.iter().map(|(_, transit)| transit.router_info()).collect(),
        );

        let pool_config = TunnelPoolConfig {
            num_inbound: 1usize,
            num_inbound_hops: 3usize,
            num_outbound: 0usize,
            num_outbound_hops: 0usize,
            destination: (),
        };
        let our_hash = {
            let mut our_hash = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut our_hash);

            Bytes::from(our_hash)
        };
        let noise = {
            let mut key_bytes = vec![0u8; 32];
            MockRuntime::rng().fill_bytes(&mut key_bytes);

            NoiseContext::new(StaticPrivateKey::from(key_bytes), our_hash.clone())
        };
        let handle = MockRuntime::register_metrics(Vec::new());
        let (manager_tx, manager_rx) = mpsc::channel(64);
        let (transit_tx, transit_rx) = mpsc::channel(64);
        let routing_table = RoutingTable::new(RouterId::from(our_hash), manager_tx, transit_tx);

        let mut tunnel_pool = TunnelPoolNew::<MockRuntime, _>::new(
            pool_config,
            ExploratorySelector::new(router_storage.clone()),
            routing_table.clone(),
            noise,
            handle.clone(),
        );

        assert!(tokio::time::timeout(Duration::from_secs(2), &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.pending_inbound.len(), 1);
        assert_eq!(tunnel_pool.pending_inbound_channels.len(), 1);

        // 1st outbound hop (ibgw)
        let (router, message) = manager_rx.try_recv().unwrap();
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 2nd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // 3rd outbound hop (participant)
        let message = Message::parse_short(&message).unwrap();
        let (router, message) =
            routers.get_mut(&router).unwrap().handle_short_tunnel_build(message).unwrap();

        // don't route the response which causes the build request to expire
        assert!(tokio::time::timeout(TUNNEL_BUILD_EXPIRATION, &mut tunnel_pool).await.is_err());
        assert_eq!(tunnel_pool.inbound.len(), 0);
        assert_eq!(MockRuntime::get_counter_value(NUM_BUILD_FAILURES), Some(1))
    }
}
