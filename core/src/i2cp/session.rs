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
    destination::{Destination, DestinationEvent, LeaseSetStatus},
    i2cp::{
        message::{
            BandwidthLimits, HostReply, HostReplyKind, Message, MessagePayload,
            RequestVariableLeaseSet, SessionId, SessionStatus, SessionStatusKind, SetDate,
        },
        payload::I2cpParameters,
        pending::I2cpSessionContext,
        socket::I2cpSocket,
    },
    i2np::{MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION},
    netdb::NetDbHandle,
    primitives::{Date, DestinationId, Lease, Str, TunnelId},
    protocol::Protocol,
    runtime::Runtime,
    tunnel::{TunnelManagerHandle, TunnelPoolEvent, TunnelPoolHandle},
};

use futures::StreamExt;
use hashbrown::{HashMap, HashSet};

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};
use rand_core::RngCore;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::i2cp::session";

/// Context for a pending outbound message.
///
/// Message is marked as outbound because a lease set query for the remote destination is pending.
struct PendingMessage {
    /// I2CP protocol parameters.
    parameters: I2cpParameters,

    /// Payload.
    payload: Vec<u8>,

    /// Session ID.
    session_id: SessionId,
}

/// I2CP client session.
pub struct I2cpSession<R: Runtime> {
    /// Destination.
    destination: Destination<R>,

    /// Active inbound tunnels and their leases.
    inbound: HashMap<TunnelId, Lease>,

    /// Handle to `NetDb`.
    netdb_handle: NetDbHandle,

    /// Next message ID.
    next_message_id: u32,

    /// Session options.
    options: HashMap<Str, Str>,

    /// Active outbound tunnels.
    outbound: HashSet<TunnelId>,

    /// Pending outbound connections.
    pending_connections: HashMap<DestinationId, VecDeque<PendingMessage>>,

    /// Session ID.
    session_id: u16,

    /// I2CP socket.
    socket: I2cpSocket<R>,

    /// Tunnel pool handle.
    tunnel_pool_handle: TunnelPoolHandle,
}

impl<R: Runtime> I2cpSession<R> {
    /// Create new [`I2cpSession`] from `stream`.
    pub fn new(netdb_handle: NetDbHandle, context: I2cpSessionContext<R>) -> Self {
        let I2cpSessionContext {
            inbound,
            outbound,
            session_id,
            mut socket,
            options,
            tunnel_pool_handle,
            private_keys,
            leaseset,
            destination_id,
        } = context;

        tracing::info!(
            target: LOG_TARGET,
            ?session_id,
            num_inbound_tunnels = ?inbound.len(),
            num_outbound_tunnels = ?outbound.len(),
            "start active i2cp session",
        );

        // TODO: remove
        for (key, value) in &options {
            tracing::info!("{key}={value}");
        }

        Self {
            destination: Destination::new(
                destination_id,
                private_keys[0].clone(),
                leaseset,
                netdb_handle.clone(),
            ),
            inbound,
            netdb_handle,
            next_message_id: 0u32,
            options,
            pending_connections: HashMap::new(),
            outbound,
            session_id,
            socket,
            tunnel_pool_handle,
        }
    }

    /// Send `MessagePayload` message to client.
    fn send_payload_message(&mut self, payload: Vec<u8>) {
        let message_id = {
            let message_id = self.next_message_id;
            self.next_message_id = self.next_message_id.wrapping_add(1);

            message_id
        };

        self.socket
            .send_message(MessagePayload::new(self.session_id, message_id, payload));
    }

    /// Handle I2CP message received from the client.
    fn on_message(&mut self, message: Message) {
        match message {
            Message::GetDate { version, options } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    %version,
                    ?options,
                    "get date, send set date",
                );

                self.socket.send_message(SetDate::new(
                    Date::new(R::time_since_epoch().as_millis() as u64),
                    Str::from_str("0.9.63").expect("to succeed"),
                ));
            }
            Message::GetBandwidthLimits => {
                tracing::trace!(
                    target: LOG_TARGET,
                    "handle bandwidth limit request",
                );

                self.socket.send_message(BandwidthLimits::new());
            }
            Message::DestroySession { session_id } => {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?session_id,
                    "destroy session",
                );

                self.socket
                    .send_message(SessionStatus::new(session_id, SessionStatusKind::Destroyed));
            }
            Message::CreateSession {
                destination,
                date,
                options,
            } => {
                tracing::warn!(
                    target: LOG_TARGET,
                    destination = %destination.id(),
                    ?date,
                    num_options = ?options.len(),
                    "received `CreateSession` for an active session",
                );

                self.socket.send_message(SessionStatus::new(
                    SessionId::Session(self.session_id),
                    SessionStatusKind::Refused,
                ));
            }
            Message::HostLookup {
                session_id,
                request_id,
                timeout,
                kind,
            } => {
                tracing::info!(
                    target: LOG_TARGET,
                    ?session_id,
                    ?request_id,
                    ?timeout,
                    ?kind,
                    "host lookup, address book not implemented",
                );

                self.socket.send_message(HostReply::new(
                    session_id.as_u16(),
                    request_id,
                    HostReplyKind::Failure,
                ));
            }
            Message::CreateLeaseSet2 {
                session_id,
                key,
                leaseset,
                private_keys,
            } => {
                tracing::debug!(
                    target: LOG_TARGET,
                    ?session_id,
                    num_private_keys = ?private_keys.len(),
                    "store leaseset to netdb",
                );

                if let Err(error) = self.netdb_handle.store_leaseset(key, leaseset) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?session_id,
                        ?error,
                        "failed to store leaseset to netdb",
                    );
                }

                // TODO: handle correctly
            }
            Message::SendMessageExpires {
                session_id,
                destination,
                parameters:
                    I2cpParameters {
                        dst_port,
                        protocol,
                        src_port,
                    },
                payload,
                ..
            } => {
                let destination_id = destination.id();

                match protocol {
                    Protocol::Streaming =>
                        match self.destination.query_lease_set(&destination_id) {
                            LeaseSetStatus::Found => {
                                tracing::trace!(
                                    target: LOG_TARGET,
                                    ?session_id,
                                    %destination_id,
                                    ?protocol,
                                    "send message with expiration",
                                );

                                if let Err(error) =
                                    self.destination.encrypt_message(&destination.id(), payload)
                                {
                                    tracing::error!(
                                        target: LOG_TARGET,
                                        session_id = ?self.session_id,
                                        ?error,
                                        "failed to encrypt message",
                                    );
                                }
                            }
                            LeaseSetStatus::NotFound => {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    %destination_id,
                                    "cannot send message, lease set doesn't exist",
                                );

                                // `Destination` has started a lease set query and will notify
                                // `I2cpConnection` once the query has completed
                                //
                                // pending messages will be sent if the lease set is found
                                self.pending_connections.insert(
                                    destination_id,
                                    VecDeque::from_iter([PendingMessage {
                                        parameters: I2cpParameters {
                                            dst_port,
                                            protocol,
                                            src_port,
                                        },
                                        payload,
                                        session_id,
                                    }]),
                                );
                            }
                            LeaseSetStatus::Pending =>
                                match self.pending_connections.get_mut(&destination_id) {
                                    Some(messages) => messages.push_back(PendingMessage {
                                        parameters: I2cpParameters {
                                            dst_port,
                                            protocol,
                                            src_port,
                                        },
                                        payload,
                                        session_id,
                                    }),
                                    None => {
                                        tracing::warn!(
                                            target: LOG_TARGET,
                                            %destination_id,
                                            "pending connection doesn't exist",
                                        );
                                        debug_assert!(false);
                                    }
                                },
                        },
                    protocol => tracing::warn!(
                        target: LOG_TARGET,
                        destination = %destination.id(),
                        ?src_port,
                        ?dst_port,
                        ?protocol,
                        "protocol not supported"
                    ),
                }
            }
            _ => {}
        }
    }

    /// Handle `event` received from the session's tunnel pool.
    fn on_tunnel_pool_event(&mut self, event: TunnelPoolEvent) {
        tracing::trace!(
            target: LOG_TARGET,
            session_id = ?self.session_id,
            ?event,
            "tunnel pool event",
        );

        match event {
            TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease } => {}
            TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id } => {}
            TunnelPoolEvent::InboundTunnelExpired { tunnel_id } => {}
            TunnelPoolEvent::OutboundTunnelExpired { tunnel_id } => {}
            TunnelPoolEvent::Message { message } => match self.destination.decrypt_message(message)
            {
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        ?error,
                        "failed to handle garlic message"
                    );
                }
                Ok(messages) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "send messages to i2cp client",
                    );

                    messages.for_each(|message| self.send_payload_message(message));
                }
            },
            TunnelPoolEvent::TunnelPoolShutDown | TunnelPoolEvent::Dummy => unreachable!(),
        }
    }
}

impl<R: Runtime> Future for I2cpSession<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.socket.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(message)) => self.on_message(message),
            }
        }

        loop {
            match self.tunnel_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "tunnel pool shut down, shutting down session",
                    );

                    return Poll::Ready(());
                }
                Poll::Ready(Some(event)) => self.on_tunnel_pool_event(event),
            }
        }

        loop {
            match self.destination.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(()),
                Poll::Ready(Some(DestinationEvent::SendMessage {
                    router_id,
                    tunnel_id,
                    message,
                })) => {
                    // wrap the garlic message inside a standard i2np message and send it over
                    // the one of the pool's outbound tunnels to remote destination
                    let message = MessageBuilder::standard()
                        .with_message_type(MessageType::Garlic)
                        .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
                        .with_message_id(R::rng().next_u32())
                        .with_payload(&message)
                        .build();

                    if let Err(error) =
                        self.tunnel_pool_handle.send_to_tunnel(router_id, tunnel_id, message)
                    {
                        tracing::debug!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            ?error,
                            "failed to send message to tunnel",
                        );
                    }
                }
                Poll::Ready(Some(DestinationEvent::LeaseSetFound { destination_id })) =>
                    match self.pending_connections.remove(&destination_id) {
                        Some(messages) => messages.into_iter().for_each(|message| {
                            if let Err(error) =
                                self.destination.encrypt_message(&destination_id, message.payload)
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    session_id = ?self.session_id,
                                    ?error,
                                    "failed to encrypt message",
                                );
                            }
                        }),
                        None => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                %destination_id,
                                "lease set query completed for a connection that doesn't exist",
                            );
                            debug_assert!(false);
                        }
                    },
                Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                    destination_id,
                    error,
                })) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %destination_id,
                        ?error,
                        "lease set query failed",
                    );
                    let _ = self.pending_connections.remove(&destination_id);
                }
            }
        }

        Poll::Pending
    }
}
