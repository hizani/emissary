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
    crypto::{base64_encode, SigningPrivateKey, StaticPrivateKey},
    destination::{Destination, DestinationEvent},
    i2cp::{I2cpPayload, I2cpPayloadBuilder},
    primitives::{Destination as Dest, LeaseSet2, LeaseSet2Header},
    protocol::Protocol,
    runtime::Runtime,
    sam::{
        parser::{DestinationKind, SamVersion},
        pending::session::SamSessionContext,
        protocol::streaming::{ListenerKind, StreamManager},
        socket::SamSocket,
    },
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use hashbrown::HashMap;
use thingbuf::mpsc::Receiver;

use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::session";

/// Recycling strategy for [`SamSessionCommand`].
#[derive(Default, Clone)]
pub(super) struct SamSessionCommandRecycle(());

impl<R: Runtime> thingbuf::Recycle<SamSessionCommand<R>> for SamSessionCommandRecycle {
    fn new_element(&self) -> SamSessionCommand<R> {
        SamSessionCommand::Dummy
    }

    fn recycle(&self, element: &mut SamSessionCommand<R>) {
        *element = SamSessionCommand::Dummy;
    }
}

/// SAMv3 session commands.
pub enum SamSessionCommand<R: Runtime> {
    /// Open virtual stream to `destination` over this connection.
    Connect {
        /// SAMv3 socket associated with the outbound stream.
        socket: SamSocket<R>,

        /// Destination.
        destination: Dest,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Accept inbond virtual stream over this connection.
    Accept {
        /// SAMv3 socket associated with the inbound stream.
        socket: SamSocket<R>,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Forward incoming virtual streams to a TCP listener listening to `port`.
    Forward {
        /// SAMv3 socket associated with forwarding.
        socket: SamSocket<R>,

        /// Port which the TCP listener is listening.
        port: u16,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Dummy event, never constructed.
    Dummy,
}

impl<R: Runtime> Default for SamSessionCommand<R> {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Active SAMv3 session.
pub struct SamSession<R: Runtime> {
    /// [`Destination`] of the session.
    destination: Destination<R>,

    /// Session options.
    options: HashMap<String, String>,

    /// Receiver for commands sent for this session.
    ///
    /// Commands are dispatched by `SamServer` which ensures that [`SamCommand::CreateSession`]
    /// is never received by an active session.
    receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

    /// Session ID.
    session_id: Arc<str>,

    /// Socket for reading session-related commands from the client.
    socket: SamSocket<R>,

    /// I2P virtual stream manager.
    stream_manager: StreamManager<R>,

    /// Negotiated SAMv3 version.
    version: SamVersion,
}

impl<R: Runtime> SamSession<R> {
    /// Create new [`SamSession`].
    pub fn new(context: SamSessionContext<R>) -> Self {
        let SamSessionContext {
            inbound,
            options,
            destination,
            outbound,
            receiver,
            session_id,
            mut socket,
            tunnel_pool_handle,
            version,
            netdb_handle,
        } = context;

        let (destination, destination_id, privkey, signing_key) = {
            let (encryption_key, signing_key, destination_id, destination) = match destination {
                DestinationKind::Transient => {
                    let mut rng = R::rng();

                    let signing_key = SigningPrivateKey::random(&mut rng);
                    let encryption_key = StaticPrivateKey::new(rng);

                    let destination = Dest::new(signing_key.public());
                    let destination_id = destination.id();

                    (encryption_key, signing_key, destination_id, destination)
                }
                DestinationKind::Persistent {
                    destination,
                    private_key,
                    signing_key,
                } => (private_key, signing_key, destination.id(), destination),
            };

            // from specification:
            //
            // "The $privkey is the base 64 of the concatenation of the Destination followed by the
            // Private Key followed by the Signing Private Key, optionally followed by the Offline
            // Signature, which is 663 or more bytes in binary and 884 or more bytes in base 64,
            // depending on signature type. The binary format is specified in Private Key File."
            let privkey = {
                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice(encryption_key.as_ref());
                out.put_slice(signing_key.as_ref());

                base64_encode(out)
            };

            // create leaseset for the destination and store it in `NetDb`
            let local_leaseset = Bytes::from(
                LeaseSet2 {
                    header: LeaseSet2Header {
                        destination: destination.clone(),
                        published: R::time_since_epoch().as_secs() as u32,
                        expires: (R::time_since_epoch() + Duration::from_secs(10 * 60)).as_secs()
                            as u32,
                    },
                    public_keys: vec![encryption_key.public()],
                    leases: inbound.values().cloned().collect(),
                }
                .serialize(&signing_key),
            );

            if let Err(error) = netdb_handle
                .store_leaseset(Bytes::from(destination_id.to_vec()), local_leaseset.clone())
            {
                tracing::warn!(
                    target: LOG_TARGET,
                    %destination_id,
                    ?error,
                    "failed to publish lease set"
                );
                todo!();
            }

            tracing::info!(
                target: LOG_TARGET,
                %session_id,
                %destination_id,
                "start active session",
            );

            (
                Destination::new(
                    destination_id.clone(),
                    encryption_key,
                    local_leaseset,
                    netdb_handle,
                    tunnel_pool_handle,
                ),
                destination_id,
                privkey,
                signing_key,
            )
        };

        socket.send_message(
            format!("SESSION STATUS RESULT=OK DESTINATION={privkey}\n").as_bytes().to_vec(),
        );

        Self {
            destination,
            options,
            receiver,
            session_id,
            socket,
            stream_manager: StreamManager::new(destination_id, signing_key),
            version,
        }
    }

    /// Handle `STREAM CONNECT`.
    ///
    /// TODO: more documentation
    fn on_stream_connect(
        &mut self,
        socket: SamSocket<R>,
        destination: Dest,
        options: HashMap<String, String>,
    ) {
        tracing::info!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            destination_id = %destination.id(),
            "connect to destination",
        );
    }
}

impl<R: Runtime> Future for SamSession<R> {
    type Output = Arc<str>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.socket.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(command)) => match command {
                    command => tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?command,
                        "ignoring command"
                    ),
                },
            }
        }

        loop {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(SamSessionCommand::Connect {
                    socket,
                    destination,
                    options,
                })) => self.on_stream_connect(socket, destination, options),
                Poll::Ready(Some(SamSessionCommand::Accept { socket, options })) =>
                    if let Err(error) =
                        self.stream_manager.register_listener(ListenerKind::Ephemeral {
                            socket,
                            silent: options
                                .get("SILENT")
                                .map_or(false, |value| value.parse::<bool>().unwrap_or(false)),
                        })
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            session_id = %self.session_id,
                            "failed to register ephemeral listener",
                        );
                    },
                Poll::Ready(Some(SamSessionCommand::Forward {
                    socket,
                    port,
                    options,
                })) =>
                    if let Err(error) =
                        self.stream_manager.register_listener(ListenerKind::Persistent {
                            socket,
                            port,
                            silent: options
                                .get("SILENT")
                                .map_or(false, |value| value.parse::<bool>().unwrap_or(false)),
                        })
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?error,
                            session_id = %self.session_id,
                            "failed to register persistent listener",
                        );
                    },
                Poll::Ready(Some(SamSessionCommand::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.stream_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some((destination_id, message))) => {
                    // TODO: src and dst ports
                    let Some(message) = I2cpPayloadBuilder::<R>::new(&message)
                        .with_protocol(Protocol::Streaming)
                        .build()
                    else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            "failed to create i2cp payload",
                        );
                        continue;
                    };

                    if let Err(error) = self.destination.send_message(&destination_id, message) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            ?error,
                            "failed to encrypt message",
                        );
                    };
                }
            }
        }

        loop {
            match self.destination.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(DestinationEvent::Messages { messages })) => messages
                    .into_iter()
                    .for_each(|message| match I2cpPayload::decompress::<R>(message) {
                        Some(I2cpPayload {
                            dst_port,
                            payload,
                            protocol,
                            src_port,
                        }) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = ?self.session_id,
                                ?src_port,
                                ?dst_port,
                                ?protocol,
                                "handle protocol payload",
                            );

                            match protocol {
                                Protocol::Streaming => {
                                    if let Err(error) =
                                        self.stream_manager.on_packet(src_port, dst_port, payload)
                                    {
                                        tracing::warn!(
                                            target: LOG_TARGET,
                                            session_id = ?self.session_id,
                                            ?src_port,
                                            ?dst_port,
                                            ?error,
                                            "failed to handle streaming protocol packet",
                                        );
                                    }
                                }
                                protocol => tracing::warn!(
                                    target: LOG_TARGET,
                                    ?protocol,
                                    "unsupported protocol",
                                ),
                            }
                        }
                        None => tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            "failed to decompress i2cp payload",
                        ),
                    }),
                Poll::Ready(Some(DestinationEvent::LeaseSetFound { destination_id })) => {
                    todo!();
                }
                Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                    destination_id,
                    error,
                })) => {
                    todo!();
                }
                Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "tunnel pool shut down, shutting down session",
                    );

                    return Poll::Ready(Arc::clone(&self.session_id));
                }
            }
        }

        Poll::Pending
    }
}
