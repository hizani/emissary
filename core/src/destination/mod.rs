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
    crypto::{SigningPrivateKey, SigningPublicKey, StaticPrivateKey},
    destination::{
        protocol::{
            streaming::{Stream, StreamEvent},
            Protocol,
        },
        session::{KeyContext, OutboundSession},
    },
    i2np::{
        database::store::{DatabaseStoreBuilder, DatabaseStoreKind, DatabaseStorePayload},
        garlic::{
            DeliveryInstructions as GarlicDeliveryInstructions, GarlicMessage, GarlicMessageBlock,
            GarlicMessageBuilder, NextKeyKind,
        },
        Message, MessageBuilder, MessageType,
    },
    primitives::{
        Destination as Dest, Lease, LeaseSet2, LeaseSet2Header, MessageId, RouterIdentity,
    },
    runtime::Runtime,
    tunnel::TunnelPoolContextHandle,
    util::gzip::{GzipEncoderBuilder, GzipPayload},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use rand_core::RngCore;
use thingbuf::mpsc::Receiver;

use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub mod protocol;
pub mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination";

/// Client destination.
pub struct Destination<R: Runtime> {
    /// Key context.
    key_context: KeyContext<R>,

    /// Metrics handle.
    metrics: R::MetricsHandle,

    /// Channel for receiving messages from the tunnel pool.
    rx: Receiver<Message>,

    /// Streaming protocol handle.
    stream: Stream<R>,

    /// Outbound ECIES-X25519-AEAD-Ratchet session.
    session: OutboundSession<R>,

    /// Tunnel pool handle.
    tunnel_pool_handle: TunnelPoolContextHandle,

    key: Vec<u8>,
    leaseset: LeaseSet2,
}

impl<R: Runtime> Destination<R> {
    /// Create new [`Destination`].
    pub fn new(
        key: Vec<u8>,
        tunnel_pool_handle: TunnelPoolContextHandle,
        rx: Receiver<Message>,
        leaseset: LeaseSet2,
        metrics: R::MetricsHandle,
    ) -> Self {
        let lease = tunnel_pool_handle.lease().expect("to succeed");
        let mut key_context = KeyContext::new();

        let signing_key = SigningPrivateKey::random(&mut R::rng());
        let verifying_key = signing_key.public();
        let destination = Dest::new(verifying_key);
        let destination_id = destination.id();

        let local_leaseset = LeaseSet2 {
            header: LeaseSet2Header {
                destination: destination.clone(),
                published: R::time_since_epoch().as_secs() as u32,
                expires: (R::time_since_epoch() + Duration::from_secs(10 * 60)).as_secs() as u32,
            },
            public_keys: vec![key_context.public_key()],
            leases: vec![lease],
        };

        let database_store = DatabaseStoreBuilder::new(
            Bytes::from(local_leaseset.header.destination.id().to_vec()),
            DatabaseStoreKind::LeaseSet2 {
                leaseset: Bytes::from(local_leaseset.serialize(&signing_key)),
            },
        )
        .build();

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
                GarlicDeliveryInstructions::Destination { hash: &key },
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

        // TODO:
        let (session, payload) = key_context.create_oubound_session(
            destination_id,
            leaseset.public_keys.get(0).unwrap().clone(),
            &payload,
        );

        let mut payload_new = BytesMut::with_capacity(payload.len() + 4);
        payload_new.put_u32(payload.len() as u32);
        payload_new.put_slice(&payload);
        let payload = payload_new.freeze().to_vec();

        let payload = MessageBuilder::standard()
            .with_expiration(R::time_since_epoch() + Duration::from_secs(10))
            .with_message_id(R::rng().next_u32())
            .with_message_type(MessageType::Garlic)
            .with_payload(&payload)
            .build();

        let Lease {
            router_id,
            tunnel_id,
            ..
        } = leaseset.leases[0].clone();

        tunnel_pool_handle.send_to_tunnel(router_id, tunnel_id, payload);

        Self {
            key,
            key_context,
            metrics,
            rx,
            session,
            tunnel_pool_handle,
            stream,
            leaseset,
        }
    }

    /// Handle garlic message send to the destination.
    fn handle_garlic_message(&mut self, message: Message) {
        let message = self.session.decrypt_message(message).unwrap();
        let message = GarlicMessage::parse(&message).unwrap();

        for block in message.blocks {
            match block {
                GarlicMessageBlock::Padding { .. } => {}
                GarlicMessageBlock::DateTime { .. } => {}
                GarlicMessageBlock::GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions,
                    message_body,
                } => {
                    assert_eq!(message_type, MessageType::Data);

                    let GzipPayload {
                        dst_port,
                        payload,
                        protocol,
                        src_port,
                    } = GzipPayload::decompress::<R>(&message_body[4..]).unwrap();

                    if let Err(error) = self.stream.handle_packet(&payload) {
                        tracing::error!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to handle streaming protocol packet",
                        );
                    }
                }
                GarlicMessageBlock::NextKey { kind } => {
                    self.session.handle_next_key(kind);
                }
                message_block => {
                    tracing::error!("\nunhandled message block {message_block:?}\n");
                }
            }
        }
    }
}

impl<R: Runtime> Future for Destination<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.rx.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(message)) => self.handle_garlic_message(message),
            }
        }

        loop {
            match self.stream.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(StreamEvent::StreamOpened {
                    recv_stream_id,
                    send_stream_id,
                })) => {
                    tracing::info!(target: LOG_TARGET, "stream opened");

                    let next_key_kind = match self.session.generate_next_key() {
                        Ok(kind) => kind,
                        Err(error) => return Poll::Ready(()),
                    };

                    for _ in 0..5 {
                        tracing::info!(target: LOG_TARGET, "SEND NEXT KEY");
                    }

                    let mut payload =
                        GarlicMessageBuilder::new().with_next_key(next_key_kind).build();

                    let payload = self.session.encrypt_message(payload).unwrap();

                    let mut payload_new = BytesMut::with_capacity(payload.len() + 4);
                    payload_new.put_u32(payload.len() as u32);
                    payload_new.put_slice(&payload);

                    let payload = payload_new.freeze().to_vec();
                    let payload = MessageBuilder::standard()
                        .with_expiration(R::time_since_epoch() + Duration::from_secs(10))
                        .with_message_id(R::rng().next_u32())
                        .with_message_type(MessageType::Garlic)
                        .with_payload(&payload)
                        .build();

                    let Lease {
                        router_id,
                        tunnel_id,
                        ..
                    } = self.leaseset.leases[0].clone();

                    self.tunnel_pool_handle.send_to_tunnel(router_id, tunnel_id, payload).unwrap();
                }
                Poll::Ready(Some(StreamEvent::StreamClosed {
                    recv_stream_id,
                    send_stream_id,
                })) => {}
                Poll::Ready(Some(StreamEvent::SendPacket { packet })) => {
                    let mut payload = GarlicMessageBuilder::new()
                        .with_garlic_clove(
                            MessageType::Data,
                            MessageId::from(R::rng().next_u32()),
                            (R::time_since_epoch() + Duration::from_secs(10)).as_secs(),
                            GarlicDeliveryInstructions::Destination { hash: &self.key },
                            &{
                                let payload = GzipEncoderBuilder::<R>::new(&packet)
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

                    let payload = self.session.encrypt_message(payload).unwrap();

                    let mut payload_new = BytesMut::with_capacity(payload.len() + 4);
                    payload_new.put_u32(payload.len() as u32);
                    payload_new.put_slice(&payload);
                    let payload = payload_new.freeze().to_vec();

                    let payload = MessageBuilder::standard()
                        .with_expiration(R::time_since_epoch() + Duration::from_secs(10))
                        .with_message_id(R::rng().next_u32())
                        .with_message_type(MessageType::Garlic)
                        .with_payload(&payload)
                        .build();

                    let Lease {
                        router_id,
                        tunnel_id,
                        ..
                    } = self.leaseset.leases[0].clone();

                    self.tunnel_pool_handle.send_to_tunnel(router_id, tunnel_id, payload).unwrap();
                }
            }
        }

        Poll::Pending
    }
}
