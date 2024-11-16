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
    crypto::StaticPrivateKey,
    destination::session::{SessionManager, SessionManagerEvent},
    error::{ChannelError, Error, QueryError, SessionError},
    i2np::{
        database::store::{DatabaseStore, DatabaseStorePayload},
        Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::NetDbHandle,
    primitives::{DestinationId, Lease, LeaseSet2},
    runtime::{Instant, JoinSet, Runtime},
    tunnel::{TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt, Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

pub mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination";

/// Retry timeout for lease set query.
const QUERY_RETRY_TIMEOUT: Duration = Duration::from_secs(5);

/// Local lease set expiration timeout.
const LEASE_SET_EXPIRATION: Duration = Duration::from_secs(9 * 60);

/// Local lease set expiration timeout.
const LEASE_SET_MAX_AGE: Duration = Duration::from_secs(2 * 60);

/// How soon is the lease set publish retried after it failed.
const LEASE_SET_REPUBLISH_TIMEOUT: Duration = Duration::from_secs(3);

/// Number of retries before lease set query is aborted.
///
/// This is the number retries made when trying to contact [`NetDb`] for a lease set query
/// in case the channel used by [`NetDbHandle`] is clogged.
const NUM_QUERY_RETRIES: usize = 3usize;

/// Events emitted by [`Destination`].
#[derive(Debug)]
pub enum DestinationEvent {
    /// One or more messages received.
    Messages {
        /// One or more I2NP Data messages.
        messages: Vec<Vec<u8>>,
    },

    /// Lease set of the remote found in NetDb.
    LeaseSetFound {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },

    /// Lease set of the remote not found in NetDb.
    LeaseSetNotFound {
        /// ID of the remote destination.
        destination_id: DestinationId,

        /// Query error.
        error: QueryError,
    },

    /// Tunnel pool shut down.
    TunnelPoolShutDown,

    /// Create new lease set from leases.
    CreateLeaseSet {
        /// Leases.
        leases: Vec<Lease>,
    },

    /// Session with remote destination has been termianted.
    SessionTerminated {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },
}

/// Lease set status of remote destination.
///
/// Remote's lease set must exist in [`Destination`] in order to send message to them.
#[derive(Debug, PartialEq, Eq)]
pub enum LeaseSetStatus {
    /// [`LeaseSet2`] for destination found in [`Destination`].
    ///
    /// Caller doesn't need to buffer messages and wait for the query to finish.
    Found,

    /// [`LeaseSet2`] for destination not found in [`Destination`].
    ///
    /// Query will be started in the backgroun and the caller is notified
    /// of the query result via [`Destination::poll_next()`].
    NotFound,

    /// Query for destination's [`LeaseSet2`] is pending.
    Pending,
}

/// Client destination.
pub struct Destination<R: Runtime> {
    /// Destination ID of the client.
    destination_id: DestinationId,

    /// Serialized [`LeaseSet2`] for client's inbound tunnels.
    lease_set: Bytes,

    /// Timer which expires when a new lease set needs to be published
    /// or an old lease set publish should be reattempted.
    lease_set_publish_timer: LeaseSetPublishTimer,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// Inbound tunnels waiting to be published to `NetDb`.
    pending_inbound: Vec<(Lease, R::Instant)>,

    /// Pending lease set queries:
    pending_queries: HashSet<DestinationId>,

    /// Pending `LeaseSet2` query futures.
    query_futures: R::JoinSet<(DestinationId, Result<LeaseSet2, QueryError>)>,

    /// Known remote destinations.
    remote_destinations: HashMap<DestinationId, LeaseSet2>,

    /// Session manager.
    session_manager: SessionManager<R>,

    /// Handle to destination's [`TunnelPool`].
    tunnel_pool_handle: TunnelPoolHandle,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> Destination<R> {
    /// Create new [`Destination`].
    ///
    /// `private_key` is the private key of the client destination and `lease`
    /// is a serialized [`LeaseSet2`] for the client's inbound tunnel(s).
    pub fn new(
        destination_id: DestinationId,
        private_key: StaticPrivateKey,
        lease_set: Bytes,
        netdb_handle: NetDbHandle,
        tunnel_pool_handle: TunnelPoolHandle,
    ) -> Self {
        Self {
            pending_inbound: Vec::new(),
            destination_id: destination_id.clone(),
            lease_set: lease_set.clone(),
            netdb_handle,
            pending_queries: HashSet::new(),
            query_futures: R::join_set(),
            remote_destinations: HashMap::new(),
            session_manager: SessionManager::new(destination_id, private_key, lease_set),
            tunnel_pool_handle,
            lease_set_publish_timer: LeaseSetPublishTimer::new::<R>(),
            waker: None,
        }
    }

    /// Look up lease set status of remote destination.
    ///
    /// Before sending a message to remote, the caller must ensure [`Destination`] holds a valid
    /// lease for the remote destination. This needs to be done only once, when sending the first
    /// message to remote destination. If this function is called when there is no active lease set
    /// for `destination`, a lease set query is started in the background and its result can be
    /// polled via [`Destinatin::poll_next()`].
    ///
    /// If this function returns [`LeaseSetStatus::Found`], [`Destination::send_message()`] can be
    /// called as the remote is reachable. If it returns [`LeaseStatus::NotFound`] or
    /// [`LeaseStatus::Pending`], the caller must wait until [`Destination`] emits
    /// [`DestinationEvent::LeaseSetFound`], indicating that a lease set is foun and the remote
    /// destination is reachable.
    pub fn query_lease_set(&mut self, destination_id: &DestinationId) -> LeaseSetStatus {
        if self.remote_destinations.contains_key(destination_id) {
            return LeaseSetStatus::Found;
        }

        if self.pending_queries.contains(destination_id) {
            return LeaseSetStatus::Pending;
        }

        tracing::trace!(
            target: LOG_TARGET,
            %destination_id,
            "lookup destination",
        );

        let handle = self.netdb_handle.clone();
        let destination_id = destination_id.clone();

        self.pending_queries.insert(destination_id.clone());
        self.query_futures.push(async move {
            for _ in 0..NUM_QUERY_RETRIES {
                let Ok(rx) = handle.query_leaseset(Bytes::from(destination_id.to_vec())) else {
                    R::delay(QUERY_RETRY_TIMEOUT).await;
                    continue;
                };

                tracing::trace!(
                    target: LOG_TARGET,
                    %destination_id,
                    "lease set query started",
                );

                match rx.await {
                    Err(_) => return (destination_id, Err(QueryError::Timeout)),
                    Ok(Err(error)) => return (destination_id, Err(error)),
                    Ok(Ok(lease_set)) => return (destination_id, Ok(lease_set)),
                }
            }

            tracing::warn!(
                target: LOG_TARGET,
                %destination_id,
                "failed to start lease set query after {NUM_QUERY_RETRIES} retries",
            );

            return (destination_id, Err(QueryError::RetryFailure));
        });

        LeaseSetStatus::NotFound
    }

    /// Send encrypted `message` to remote `destination`.
    ///
    /// Lease set for the remote destination must exist in [`Destination`], otherwise the call is
    /// rejected. Lease set can be queried with [`Destination::query_lease_set()`] which returns a
    /// result indicating whether the remote is "reachable" right now.
    ///
    /// After the message has been encrypted, it's sent to remote destination via one of the
    /// outbound tunnels of [`Destination`].
    fn send_message_inner(
        &mut self,
        destination_id: &DestinationId,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        let Some(LeaseSet2 { leases, .. }) = self.remote_destinations.get(destination_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                %destination_id,
                "`Destination::encrypt()` called but lease set is missing",
            );
            debug_assert!(false);
            return Err(Error::InvalidState);
        };

        // wrap the garlic message inside a standard i2np message and send it over
        // the one of the pool's outbound tunnels to remote destination
        let message = MessageBuilder::standard()
            .with_message_type(MessageType::Garlic)
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_id(R::rng().next_u32())
            .with_payload(&message)
            .build();

        if let Err(error) = self.tunnel_pool_handle.send_to_tunnel(
            leases[0].router_id.clone(),
            leases[0].tunnel_id,
            message,
        ) {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                reomte = %destination_id,
                ?error,
                "failed to send message to tunnel",
            );
        }

        Ok(())
    }

    /// Encrypt and send `message` to remote destination.
    ///
    /// Session manager is expected to have public key of the remote destination.
    pub fn send_message(
        &mut self,
        destination_id: &DestinationId,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        match self.session_manager.encrypt(destination_id, message) {
            Ok(message) => self.send_message_inner(destination_id, message),
            Err(error) => Err(Error::Session(error)),
        }
    }

    /// Handle garlic messages received into one of the [`Destination`]'s inbound tunnels.
    ///
    /// The decrypted garlic message may contain a database store for an up-to-date [`LeaseSet2`] of
    /// the remote destination and if so, the currently stored lease set is overriden with the new
    /// lease set.
    ///
    /// Any garlic clove containing an I2NP Data message is returned to user.
    fn decrypt_message(&mut self, message: Message) -> crate::Result<Vec<Vec<u8>>> {
        tracing::trace!(
            target: LOG_TARGET,
            message_id = ?message.message_id,
            "garlic message",
        );
        debug_assert_eq!(message.message_type, MessageType::Garlic);

        if message.payload.len() <= 12 {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                payload_len = ?message.payload.len(),
                "garlic message is too short",
            );
            return Err(Error::InvalidData);
        }

        Ok(self
            .session_manager
            .decrypt(message)
            .map_err(|error| Error::Session(error))?
            .filter_map(|clove| match clove.message_type {
                MessageType::DatabaseStore => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "remote lease set received",
                    );

                    match DatabaseStore::<R>::parse(&clove.message_body) {
                        Some(DatabaseStore {
                            payload: DatabaseStorePayload::LeaseSet2 { leaseset },
                            ..
                        }) => {
                            if leaseset.leases.is_empty() {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    local = %self.destination_id,
                                    remote = %leaseset.header.destination.id(),
                                    "remote didn't send any leases",
                                );
                                return None;
                            }

                            tracing::trace!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %leaseset.header.destination.id(),
                                "store lease set for remote destination",
                            );

                            self.remote_destinations
                                .insert(leaseset.header.destination.id(), leaseset);
                        }
                        database_store => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                ?database_store,
                                "ignoring `DatabaseStore`",
                            )
                        }
                    }

                    None
                }
                MessageType::Data => {
                    if clove.message_body.len() <= 4 {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "empty i2np data message",
                        );
                        debug_assert!(false);
                        return None;
                    }

                    Some(clove.message_body[4..].to_vec())
                }
                _ => None,
            })
            .collect::<Vec<_>>())
    }

    /// Attempt to publish new lease set to `NetDb`.
    pub fn publish_lease_set(&mut self, key: Bytes, lease_set: Bytes) {
        match self.netdb_handle.store_leaseset(key.clone(), lease_set.clone()) {
            Ok(()) => {
                self.lease_set = lease_set.clone();
                self.lease_set_publish_timer.reset::<R>();
                self.session_manager.set_local_leaseset(lease_set);
            }
            Err(ChannelError::Full) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    "channel to netdb is clogged, try publishing lease set later",
                );
                self.lease_set_publish_timer.retry::<R>(key, lease_set);

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
            Err(error) => tracing::error!(
                target: LOG_TARGET,
                local = %self.destination_id,
                ?error,
                "failed to publish lease set",
            ),
        }
    }
}

impl<R: Runtime> Stream for Destination<R> {
    type Item = DestinationEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.tunnel_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) =>
                    return Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown)),
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease })) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        ?tunnel_id,
                        "inbound tunnel built",
                    );
                    self.pending_inbound.push((lease, R::now()));

                    // return event before the publish timer expires if there are enough leases
                    if self
                        .pending_inbound
                        .iter()
                        .filter(|(_, created)| created.elapsed() < LEASE_SET_MAX_AGE)
                        .count()
                        == self.tunnel_pool_handle.config().num_inbound
                    {
                        // reset timer so it doesn't fire when the client is creating the lease set
                        self.lease_set_publish_timer.deactivate();

                        let leases = mem::replace(&mut self.pending_inbound, Vec::new())
                            .into_iter()
                            .filter_map(|(lease, created)| {
                                (created.elapsed() < LEASE_SET_MAX_AGE).then_some(lease)
                            })
                            .collect::<Vec<_>>();

                        return Poll::Ready(Some(DestinationEvent::CreateLeaseSet { leases }));
                    }
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { .. })) => {}
                Poll::Ready(Some(TunnelPoolEvent::Message { message })) =>
                    match self.decrypt_message(message) {
                        Err(error) => tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "failed to decrypt garlic message",
                        ),
                        Ok(messages) if !messages.is_empty() =>
                            return Poll::Ready(Some(DestinationEvent::Messages { messages })),
                        Ok(_) => {}
                    },
                Poll::Ready(Some(TunnelPoolEvent::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.session_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(SessionManagerEvent::SessionTerminated { destination_id })) =>
                    return Poll::Ready(Some(DestinationEvent::SessionTerminated {
                        destination_id,
                    })),
                Poll::Ready(Some(SessionManagerEvent::SendMessage {
                    destination_id,
                    message,
                })) =>
                    if let Err(error) = self.send_message_inner(&destination_id, message) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "failed to send message",
                        );
                    },
            }
        }

        loop {
            match self.query_futures.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some((destination_id, result))) => match result {
                    Err(error) => {
                        self.pending_queries.remove(&destination_id);
                        return Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                            destination_id,
                            error,
                        }));
                    }
                    Ok(lease_set) => {
                        self.pending_queries.remove(&destination_id);
                        self.session_manager.add_remote_destination(
                            destination_id.clone(),
                            lease_set.public_keys[0].clone(),
                        );
                        self.remote_destinations.insert(destination_id.clone(), lease_set);

                        return Poll::Ready(Some(DestinationEvent::LeaseSetFound {
                            destination_id,
                        }));
                    }
                },
            }
        }

        match self.lease_set_publish_timer.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(LeaseSetPublishTimerEvent::CreateNew)) => {
                let leases = mem::replace(&mut self.pending_inbound, Vec::new())
                    .into_iter()
                    .filter_map(|(lease, created)| {
                        (created.elapsed() < LEASE_SET_MAX_AGE).then_some(lease)
                    })
                    .collect::<Vec<_>>();

                return Poll::Ready(Some(DestinationEvent::CreateLeaseSet { leases }));
            }
            Poll::Ready(Some(LeaseSetPublishTimerEvent::Republish { key, lease_set })) => {
                self.publish_lease_set(key, lease_set);
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// Events emitted by [`LeaseSetPublishTimer`].
enum LeaseSetPublishTimerEvent {
    /// Create new lease set.
    CreateNew,

    /// Attempt to republish old lease set.
    Republish {
        /// Key.
        key: Bytes,
        /// Lease set.
        lease_set: Bytes,
    },
}

/// Lease set publish timer.
enum LeaseSetPublishTimer {
    /// TImer is inactive.
    Inactive,

    /// Create new lease set.
    CreateNew {
        /// Timer.
        timer: BoxFuture<'static, ()>,
    },

    /// Attempt to retry publishing an old lease set.
    Republish {
        // Timer.
        timer: BoxFuture<'static, ()>,

        /// Key.
        key: Bytes,

        /// Lease set.
        lease_set: Bytes,
    },
}

impl LeaseSetPublishTimer {
    /// Create new [`LeaseSetPublishTimer`].
    fn new<R: Runtime>() -> Self {
        Self::CreateNew {
            timer: Box::pin(R::delay(LEASE_SET_EXPIRATION)),
        }
    }

    /// Reset timer.
    fn reset<R: Runtime>(&mut self) {
        *self = Self::CreateNew {
            timer: Box::pin(R::delay(LEASE_SET_EXPIRATION)),
        };
    }

    /// Set timer in republish mode.
    fn retry<R: Runtime>(&mut self, key: Bytes, lease_set: Bytes) {
        *self = Self::Republish {
            timer: Box::pin(R::delay(LEASE_SET_REPUBLISH_TIMEOUT)),
            key,
            lease_set,
        };
    }

    /// Set timer as inactive.
    fn deactivate(&mut self) {
        *self = Self::Inactive;
    }
}

impl Stream for LeaseSetPublishTimer {
    type Item = LeaseSetPublishTimerEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = Pin::into_inner(self);

        match &mut this {
            LeaseSetPublishTimer::Inactive => {}
            LeaseSetPublishTimer::CreateNew { ref mut timer } => {
                if timer.poll_unpin(cx).is_ready() {
                    *this = LeaseSetPublishTimer::Inactive;
                    return Poll::Ready(Some(LeaseSetPublishTimerEvent::CreateNew));
                }
            }
            LeaseSetPublishTimer::Republish {
                timer,
                key,
                lease_set,
            } =>
                if timer.poll_unpin(cx).is_ready() {
                    let key = key.clone();
                    let lease_set = lease_set.clone();

                    *this = LeaseSetPublishTimer::Inactive;

                    return Poll::Ready(Some(LeaseSetPublishTimerEvent::Republish {
                        key,
                        lease_set,
                    }));
                },
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::{RouterId, TunnelId},
        runtime::{mock::MockRuntime, Runtime},
        tunnel::TunnelPoolConfig,
    };

    #[tokio::test]
    async fn query_lease_set_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
        );

        // insert dummy lease set for `remote` into `Destination`
        let remote = DestinationId::random();
        let (lease_set, _) = LeaseSet2::random();
        destination.remote_destinations.insert(remote.clone(), lease_set);

        // query lease set and verify it exists
        assert_eq!(destination.query_lease_set(&remote), LeaseSetStatus::Found);
    }

    #[tokio::test]
    async fn query_lease_set_not_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
        );

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);
    }

    #[tokio::test]
    async fn query_lease_set_pending() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
        );

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);

        // verify that the status is pending on subsequent queries
        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::Pending
        );
    }

    #[tokio::test]
    async fn query_lease_set_channel_clogged() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
        );

        // spam the netdb handle full of queries
        loop {
            if netdb_handle.query_leaseset(Bytes::new()).is_err() {
                break;
            }
        }

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();
        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);

        match destination.next().await {
            Some(DestinationEvent::LeaseSetNotFound {
                destination_id,
                error,
            }) => {
                assert_eq!(destination_id, remote);
                assert_eq!(error, QueryError::RetryFailure)
            }
            _ => panic!("invalid event"),
        }
    }

    #[test]
    #[should_panic]
    fn encrypt_message_lease_set_not_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle,
            tp_handle,
        );

        destination.send_message(&DestinationId::random(), vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn create_lease_set_immediately() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, tp_tx, _srx) = TunnelPoolHandle::create();
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
        );

        // new inbound tunnel built
        tp_tx
            .send(TunnelPoolEvent::InboundTunnelBuilt {
                tunnel_id: TunnelId::random(),
                lease: Lease {
                    router_id: RouterId::random(),
                    tunnel_id: TunnelId::random(),
                    expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                },
            })
            .await
            .unwrap();

        // verify event is emitted even though the timer is still active
        assert!(std::matches!(
            destination.lease_set_publish_timer,
            LeaseSetPublishTimer::CreateNew { .. }
        ));
        futures::future::poll_fn(|cx| {
            match destination.lease_set_publish_timer.poll_next_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                _ => panic!("timer is ready"),
            }
        })
        .await;

        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { leases } => {}
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn create_lease_set_after_timeout() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 3usize,
            ..Default::default()
        });
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
        );

        // set lease set timer to a more sensible value
        destination.lease_set_publish_timer = LeaseSetPublishTimer::CreateNew {
            timer: Box::pin(MockRuntime::delay(Duration::from_secs(5))),
        };

        // issue events for two new inbound tunnels
        for _ in 0..2 {
            tp_tx
                .send(TunnelPoolEvent::InboundTunnelBuilt {
                    tunnel_id: TunnelId::random(),
                    lease: Lease {
                        router_id: RouterId::random(),
                        tunnel_id: TunnelId::random(),
                        expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                    },
                })
                .await
                .unwrap();
        }

        // verify that inbound tunnel is not built because 3 inbound tunnels are needed
        assert!(destination.next().now_or_never().is_none());

        // verify that that an event is emitted after the timer expires
        match tokio::time::timeout(Duration::from_secs(15), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { leases } => {}
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test]
    async fn lease_set_publish_retried() {
        crate::util::init_logger();

        let (netdb_handle, mut rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 3usize,
            ..Default::default()
        });
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            StaticPrivateKey::new(MockRuntime::rng()),
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
        );

        // spam the netdb channel full of data
        while let Ok(_) = netdb_handle.store_leaseset(Bytes::new(), Bytes::new()) {}

        // set lease set timer to a more sensible value
        destination.lease_set_publish_timer = LeaseSetPublishTimer::CreateNew {
            timer: Box::pin(MockRuntime::delay(Duration::from_secs(5))),
        };

        // issue events for two new inbound tunnels
        for _ in 0..2 {
            tp_tx
                .send(TunnelPoolEvent::InboundTunnelBuilt {
                    tunnel_id: TunnelId::random(),
                    lease: Lease {
                        router_id: RouterId::random(),
                        tunnel_id: TunnelId::random(),
                        expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                    },
                })
                .await
                .unwrap();
        }

        // verify that inbound tunnel is not built because 3 inbound tunnels are needed
        assert!(destination.next().now_or_never().is_none());

        // verify that that an event is emitted after the timer expires
        match tokio::time::timeout(Duration::from_secs(15), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { leases } => {}
            _ => panic!("invalid event"),
        }

        destination.publish_lease_set(Bytes::from(vec![1, 2, 3]), Bytes::from(vec![4, 5, 6]));
        assert!(std::matches!(
            destination.lease_set_publish_timer,
            LeaseSetPublishTimer::Republish { .. }
        ));

        // drain events from netdb queue, giving space for the lease set publication
        while let Ok(_) = rx.try_recv() {}

        // poll destination for 5 seconds, allowing it to republish the destination
        tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .unwrap_err();

        // poll lease set store
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no timeout")
            .expect("to succeed");
    }
}
