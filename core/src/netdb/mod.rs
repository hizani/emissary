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
    crypto::{
        base32_decode, base64_decode, chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256,
        SigningPrivateKey, StaticPrivateKey, StaticPublicKey,
    },
    i2np::{
        database::{
            lookup::{DatabaseLookupBuilder, LookupType},
            store::{DatabaseStore, DatabaseStoreBuilder, DatabaseStorePayload},
        },
        garlic::{DeliveryInstructions as GarlicDeliveryInstructions, GarlicMessageBuilder},
        Message, MessageBuilder, MessageType,
    },
    netdb::{dht::Dht, metrics::*},
    primitives::{
        Lease2, LeaseSet2, LeaseSet2Header, MessageId, RouterId, RouterIdentity, RouterInfo,
    },
    protocol::{streaming::Stream, Protocol},
    router_storage::RouterStorage,
    runtime::{Counter, Gauge, MetricType, MetricsHandle, Runtime},
    session::{KeyContext, OutboundSession},
    subsystem::SubsystemEvent,
    transports::TransportService,
    tunnel::TunnelPoolHandle,
    util::gzip::GzipEncoderBuilder,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use futures::{FutureExt, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand_core::RngCore;
use thingbuf::mpsc;

use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

mod bucket;
mod dht;
mod metrics;
mod routing_table;
mod types;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::netdb";

/// Floodfill state.
#[derive(Debug)]
pub enum RouterState {
    /// FloodFill is connected.
    Connected,

    /// FloodFill is being dialed.
    Dialing {
        /// Pending messages.
        pending_messages: Vec<Vec<u8>>,
    },
}

/// Network database (NetDB).
pub struct NetDb<R: Runtime> {
    /// Kademlia DHT implementation.
    dht: Dht<R>,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Router storage.
    router_storage: RouterStorage,

    /// Connected floodfills.
    routers: HashMap<RouterId, RouterState>,

    /// Transport service.
    service: TransportService,

    /// Exploratory tunnel pool handle.
    exploratory_pool_handle: TunnelPoolHandle,

    key: Vec<u8>,
    timer: futures::future::BoxFuture<'static, ()>,
    local_router_id: RouterId,
    key_context: KeyContext<R>,
    rx: mpsc::Receiver<Message>,
    tmp: Option<(OutboundSession, Stream<R>)>,
}

impl<R: Runtime> NetDb<R> {
    /// Create new [`NetDb`].
    pub fn new(
        local_router_id: RouterId,
        service: TransportService,
        router_storage: RouterStorage,
        metrics: R::MetricsHandle,
        exploratory_pool_handle: TunnelPoolHandle,
        rx: mpsc::Receiver<Message>,
    ) -> Self {
        let floodfills = router_storage
            .routers()
            .iter()
            .filter_map(|(id, router)| router.is_floodfill().then_some(id.clone()))
            .collect::<HashSet<_>>();

        metrics.counter(NUM_FLOODFILLS).increment(floodfills.len());

        tracing::trace!(
            target: LOG_TARGET,
            num_floodfills = ?floodfills.len(),
            "starting netdb",
        );

        let key = "larnrirsp5fikx7n6fg3aczdxrurt5nyaaleqo4vqmnuo3xd5qeq";
        let key = base32_decode(&key).unwrap();

        Self {
            key_context: KeyContext::new(),
            dht: Dht::new(local_router_id.clone(), floodfills, metrics.clone()),
            exploratory_pool_handle,
            timer: Box::pin(R::delay(core::time::Duration::from_secs(20))),
            local_router_id,
            key,
            metrics,
            routers: HashMap::new(),
            router_storage,
            service,
            rx,
            tmp: None,
        }
    }

    /// Collect `NetDb`-related metric counters, gauges and histograms.
    pub fn metrics(metrics: Vec<MetricType>) -> Vec<MetricType> {
        metrics::register_metrics(metrics)
    }

    /// Handle established connection to `router`.
    fn on_connection_established(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            None =>
                match self.router_storage.get(&router_id).expect("router to exist").is_floodfill() {
                    true => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %router_id,
                            "new floodfill connected",
                        );

                        // insert new floodfills into `Dht` as well
                        self.dht.add_floodfill(router_id.clone());

                        self.routers.insert(router_id, RouterState::Connected);
                        self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
                        self.metrics.counter(NUM_FLOODFILLS).increment(1);
                    }
                    false => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            %router_id,
                            "connection established",
                        );
                    }
                },
            Some(state) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "known floodfill connected",
                );

                // "insert" floodfill into `Dht` so their "last active" status gets updated
                self.dht.add_floodfill(router_id.clone());

                self.routers.insert(router_id, RouterState::Connected);
                self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).increment(1);
            }
        }
    }

    /// Handle closed connection to `router`.
    fn on_connection_closed(&mut self, router_id: RouterId) {
        match self.routers.remove(&router_id) {
            None => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %router_id,
                    "connection closed",
                );
            }
            Some(_) => {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    "floodfill disconnected",
                );

                self.routers.remove(&router_id);
                self.metrics.gauge(NUM_CONNECTED_FLOODFILLS).decrement(1);
            }
        }
    }

    /// Handle I2NP message.
    fn on_message(&mut self, message: Message) {
        match message.message_type {
            MessageType::DatabaseStore => {
                let DatabaseStore {
                    key,
                    payload,
                    reply,
                    ..
                } = DatabaseStore::<R>::parse(&message.payload).unwrap();

                tracing::trace!("database store");

                let leaseset = match payload {
                    DatabaseStorePayload::RouterInfo { router_info } => {
                        tracing::warn!("ignore routerinfo");
                        return;
                    }
                    DatabaseStorePayload::LeaseSet2 { leaseset } => leaseset,
                };

                tracing::info!("leases = {:?}", leaseset.leases);
                tracing::info!("public keys = {:?}", leaseset.public_keys);

                let lease = self.exploratory_pool_handle.lease().expect("to succeed");

                let signing_key = SigningPrivateKey::new(&[1u8; 32]).unwrap();
                let destination = RouterIdentity::from_keys(vec![0u8; 32], vec![1u8; 32]).unwrap();
                let sk = StaticPrivateKey::from([0u8; 32]);

                let local_leaseset = LeaseSet2 {
                    header: LeaseSet2Header {
                        destination: destination.clone(),
                        published: R::time_since_epoch().as_secs() as u32,
                        expires: (R::time_since_epoch() + Duration::from_secs(10 * 60)).as_secs()
                            as u32,
                    },
                    public_keys: vec![sk.public()],
                    leases: vec![lease],
                };

                let database_store = DatabaseStoreBuilder::new(
                    Into::<Vec<u8>>::into(local_leaseset.header.destination.id()),
                    DatabaseStorePayload::LeaseSet2 {
                        leaseset: local_leaseset,
                    },
                )
                .build(&signing_key);

                tracing::error!("database_store: {database_store:?}");

                let (stream, payload) = Stream::<R>::new_outbound(destination);

                let mut payload = GarlicMessageBuilder::new()
                    .with_date_time(R::time_since_epoch().as_secs() as u32)
                    .with_garlic_clove(
                        MessageType::DatabaseStore,
                        MessageId::from(R::rng().next_u32()),
                        (R::time_since_epoch() + Duration::from_secs(10)).as_secs(),
                        GarlicDeliveryInstructions::Local,
                        &database_store,
                    )
                    .with_garlic_clove(
                        MessageType::Data,
                        MessageId::from(R::rng().next_u32()),
                        (R::time_since_epoch() + Duration::from_secs(10)).as_secs(),
                        GarlicDeliveryInstructions::Destination { hash: &self.key },
                        &{
                            let payload = GzipEncoderBuilder::<R>::new(&payload)
                                .with_source_port(0)
                                .with_destination_port(0)
                                .with_protocol(Protocol::Streaming.as_u8())
                                .build()
                                .unwrap();

                            let mut out = BytesMut::with_capacity(payload.len() + 4);

                            out.put_u32(payload.len() as u32);
                            out.put_slice(&payload);

                            out.freeze().to_vec()
                        },
                    )
                    .build();

                let (session, payload) = self
                    .key_context
                    .create_oubound_session(leaseset.public_keys.get(0).unwrap().clone(), &payload);

                let mut payload_new = BytesMut::with_capacity(payload.len() + 4);
                payload_new.put_u32(payload.len() as u32);
                payload_new.put_slice(&payload);
                let payload = payload_new.freeze().to_vec();

                let payload = MessageBuilder::standard()
                    .with_expiration((R::time_since_epoch() + Duration::from_secs(10)).as_secs())
                    .with_message_id(R::rng().next_u32())
                    .with_message_type(MessageType::Garlic)
                    .with_payload(&payload)
                    .build();

                let Lease2 {
                    router_id,
                    tunnel_id,
                    ..
                } = leaseset.leases[0].clone();

                self.exploratory_pool_handle.send_to_tunnel(router_id, tunnel_id, payload);
                self.tmp = Some((session, stream));

                tracing::error!("message sent!");
            }
            MessageType::DatabaseLookup => {
                tracing::trace!("database lookup");
            }
            MessageType::DatabaseSearchReply => {
                tracing::trace!("database search reply");
            }
            message_type => tracing::warn!(
                target: LOG_TARGET,
                ?message_type,
                "unsupported message",
            ),
        }
    }

    // TODO: move this to `OutboundSession::handle_session_reply()`
    fn handle_garlic_response(&mut self, message: Message) {
        let garlic_tag = message.payload[4..12].to_vec();
        let public_key = TryInto::<[u8; 32]>::try_into(&message.payload[12..44]).unwrap();
        let mut ciphertext =
            TryInto::<[u8; 16]>::try_into(&message.payload[44..60]).unwrap().to_vec();
        let mut payload = message.payload[60..].to_vec();
        let new_pubkey =
            Randomized::from_representative(&public_key).unwrap().to_montgomery().to_bytes();
        let pubkey = StaticPublicKey::from(new_pubkey);
        let sk = StaticPrivateKey::from([0u8; 32]);

        let state = self.tmp.as_ref().unwrap().0.state.to_vec();

        let state = Sha256::new().update(&state).update(&garlic_tag).finalize();
        let state = Sha256::new().update(&state).update(&new_pubkey).finalize();

        let shared_secret = self.tmp.as_ref().unwrap().0.private_key.diffie_hellman(&pubkey);

        let mut temp_key = Hmac::new(&self.tmp.as_ref().unwrap().0.chaining_key)
            .update(&shared_secret)
            .finalize();
        let mut chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();

        let shared = sk.diffie_hellman(&pubkey);

        let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
        let mut chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();
        let keydata = Hmac::new(&temp_key)
            .update(&chaining_key)
            .update(&b"")
            .update(&[0x02])
            .finalize();
        let new_state = Sha256::new().update(&state).update(&ciphertext).finalize();

        ChaChaPoly::new(&keydata).decrypt_with_ad(&state, &mut ciphertext).unwrap();

        let state = new_state;

        let temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let send_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let recv_key = Hmac::new(&temp_key).update(&send_key).update(&[0x02]).finalize();

        // TODO: `DH_INITIALIZE` send keys
        // TODO: `DH_INITIALIZE` recv keys

        let mut temp_key = Hmac::new(&recv_key).update(&[]).finalize();
        let mut payload_key =
            Hmac::new(&temp_key).update(&b"AttachPayloadKDF").update(&[0x01]).finalize();

        ChaChaPoly::new(&payload_key).decrypt_with_ad(&state, &mut payload).unwrap();
    }
}

impl<R: Runtime> Future for NetDb<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(_) = self.timer.poll_unpin(cx) {
            let key = self.key.clone();
            let floodfills = self.dht.closest(&key, 5usize).collect::<Vec<_>>();

            let message =
                DatabaseLookupBuilder::new(key, self.local_router_id.clone(), LookupType::Leaseset)
                    .build();

            let message_id = R::rng().next_u32();
            let message = MessageBuilder::short()
                .with_expiration(
                    (R::time_since_epoch() + core::time::Duration::from_secs(8)).as_secs(),
                )
                .with_message_type(MessageType::DatabaseLookup)
                .with_message_id(message_id)
                .with_payload(&message)
                .build();

            tracing::error!(
                ?message_id,
                "send query to closest floodfills = {floodfills:?}"
            );

            if let Err(error) = self.service.send(&floodfills[0], message) {
                tracing::error!("failed to send message");
            }

            self.timer = Box::pin(R::delay(core::time::Duration::from_secs(15)));
            let _ = self.timer.poll_unpin(cx);
        }

        loop {
            match self.rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(message)) => self.handle_garlic_response(message),
            }
        }

        loop {
            match self.service.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(SubsystemEvent::I2Np { messages })) =>
                    messages.into_iter().for_each(|message| self.on_message(message)),
                Poll::Ready(Some(SubsystemEvent::ConnectionEstablished { router })) =>
                    self.on_connection_established(router),
                Poll::Ready(Some(SubsystemEvent::ConnectionClosed { router })) =>
                    self.on_connection_closed(router),
                _ => {}
            }
        }
    }
}
