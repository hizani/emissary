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
    error::StreamingError,
    primitives::DestinationId,
    runtime::{AsyncRead, AsyncWrite, Runtime},
    sam::protocol::streaming::{
        config::StreamConfig,
        packet::{Packet, PacketBuilder},
    },
};

use futures::{future::BoxFuture, FutureExt};
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use core::{
    future::Future,
    marker::PhantomData,
    mem,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::streaming::active";

/// Read buffer size.
const READ_BUFFER_SIZE: usize = 8192;

/// Initial ACK delay.
const INITIAL_ACK_DELAY: Duration = Duration::from_millis(200);

/// Sequence number for a plain ACK message.
const PLAIN_ACK: u32 = 0u32;

/// MTU size.
const MTU: usize = 1812usize;

/// Initial window size.
const INITIAL_WINDOW_SIZE: usize = 1usize;

/// Maximum window size in packets.
const MAX_WINDOW_SIZE: usize = 128usize;

/// How far ahead of the current highest received sequence number is a packet accepted.
const MAX_WINDOW_LOOKAHEAD: usize = 4 * MAX_WINDOW_SIZE;

/// Delay request which indicates choking.
const CHOKING_REQUEST: u16 = 60_001u16;

/// Maximum number of NACKs sent.
const MAX_NACKS: usize = 255usize;

/// Stream kind.
pub enum StreamKind {
    /// Stream is uninitialized and there has been no activity on it before.
    Inbound {
        /// Payload of the `SYN` packet, may be empty.
        payload: Vec<u8>,
    },

    /// Stream was pending before a listener was ready to accept it and there may have been data
    /// exchange in stream before the listener was ready. [`Stream`] must initialize its state
    /// using with the provided data.
    InboundPending {
        /// Selected send stream ID.
        send_stream_id: u32,

        /// Remote peer's current sequence number.
        seq_nro: u32,

        /// Received packets, if any.
        packets: VecDeque<Vec<u8>>,
    },

    /// Outbound stream.
    Outbound {
        /// Selected send stream ID.
        send_stream_id: u32,
    },
}

/// Context needed to initialize [`Stream`].
pub struct StreamContext {
    /// RX channel for receiving [`Packet`]s from the network.
    pub cmd_rx: Receiver<Vec<u8>>,

    /// TX channel for sending [`Packet`]s to the network.
    pub event_tx: Sender<(DestinationId, Vec<u8>)>,

    /// ID of the local destination.
    pub local: DestinationId,

    /// Stream ID selected by the stream originator.
    pub recv_stream_id: u32,

    /// ID of the remote destination.
    pub remote: DestinationId,
}

/// Write state.
enum WriteState {
    /// Get next message from channel.
    GetMessage,

    /// Send message into the socket.
    WriteMessage {
        /// Offset into `message`.
        offset: usize,

        /// Message.
        message: Vec<u8>,
    },

    /// [`WriteState`] has been poisoned.
    Poisoned,
}

/// Read state.
enum SocketState {
    /// Read message from client.
    ReadMessage,

    /// Sending message
    SendMessage {
        /// Offset into read buffer.
        offset: usize,
    },

    /// Awaiting ACK to be received for the sent message.
    AwaitingAck {
        /// Sequence number of the message.
        seq_nro: u32,

        /// Serialized packet.
        packet: Vec<u8>,
    },

    /// [`SocketState`] has been poisoned.
    Poisoned,
}

/// Inbound context.
pub struct InboundContext<R: Runtime> {
    /// ACK timer.
    ack_timer: Option<BoxFuture<'static, ()>>,

    /// Sequence number of the highest, last ACKed packet.
    //
    // TODO; what is this used for?
    last_acked: u32,

    /// Missing packets.
    missing: BTreeSet<u32>,

    /// Pending packets.
    pending: BTreeMap<u32, Vec<u8>>,

    /// Ready packets.
    ready: VecDeque<Vec<u8>>,

    /// Measured RTT.
    rtt: Duration,

    /// Highest received sequence number from remote destination.
    seq_nro: u32,

    /// Close requested, either by client or remote peer.
    close_requested: bool,

    /// Marker for `Runtime`.
    _runtime: PhantomData<R>,
}

impl<R: Runtime> InboundContext<R> {
    /// Create new [`InboundContext`] with highest received `seq_nro`.
    fn new(seq_nro: u32) -> Self {
        Self {
            ack_timer: None,
            last_acked: seq_nro,
            missing: BTreeSet::new(),
            pending: BTreeMap::new(),
            ready: VecDeque::new(),
            rtt: INITIAL_ACK_DELAY,
            close_requested: false,
            seq_nro,
            _runtime: Default::default(),
        }
    }

    // TODO: so ugly
    fn handle_packet(&mut self, seq_nro: u32, payload: Vec<u8>) -> Result<(), StreamingError> {
        // packet received in order
        if seq_nro == self.seq_nro + 1 {
            self.missing.remove(&seq_nro);
            if self.missing.is_empty() {
                self.ready.push_back(payload);
            } else {
                self.pending.insert(seq_nro, payload);
            }
            self.seq_nro = seq_nro;

            if self.ack_timer.is_none() {
                self.ack_timer = Some(Box::pin(R::delay(self.rtt)));
            }

            return Ok(());
        }

        if seq_nro > self.seq_nro + 1 {
            if (seq_nro - self.seq_nro - 1) as usize > MAX_WINDOW_LOOKAHEAD {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?seq_nro,
                    next_seq_nro = ?(self.seq_nro + 1),
                    "packet is too far in the future",
                );

                return Err(StreamingError::SequenceNumberTooHigh);
            }

            tracing::trace!(
                target: LOG_TARGET,
                ?seq_nro,
                expected = ?self.seq_nro + 1,
                "received out-of-order packet",
            );

            (self.seq_nro + 1..seq_nro).for_each(|seq_nro| {
                tracing::trace!(
                    target: LOG_TARGET,
                    ?seq_nro,
                    "marking packet as missing",
                );

                if !self.pending.contains_key(&seq_nro) {
                    self.missing.insert(seq_nro);
                }
            });

            self.pending.insert(seq_nro, payload);
            self.missing.remove(&seq_nro);
            self.seq_nro = seq_nro;

            if self.ack_timer.is_none() {
                self.ack_timer = Some(Box::pin(R::delay(self.rtt)));
            }
        } else {
            if self.missing.first() == Some(&seq_nro) {
                self.ready.push_back(payload);
                self.missing.remove(&seq_nro);

                let mut next_seq = seq_nro + 1;

                loop {
                    match self.pending.remove(&next_seq) {
                        Some(payload) => {
                            self.ready.push_back(payload);
                            next_seq += 1;
                        }
                        None => break,
                    }
                }

                if self.ack_timer.is_none() {
                    self.ack_timer = Some(Box::pin(R::delay(self.rtt)));
                }
            } else {
                self.missing.remove(&seq_nro);
                self.pending.insert(seq_nro, payload);

                if self.ack_timer.is_none() {
                    self.ack_timer = Some(Box::pin(R::delay(self.rtt)));
                }
            }
        }

        Ok(())
    }

    fn set_rtt(&mut self, rtt: usize) {
        todo!();
    }

    fn pop_message(&mut self) -> Option<Vec<u8>> {
        self.ready.pop_front()
    }

    fn close(&mut self) {
        self.close_requested = true;
    }

    fn can_close(&self) -> bool {
        self.close_requested && self.missing.is_empty()
    }
}

impl<R: Runtime> Future for InboundContext<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(timer) = &mut self.ack_timer {
            if timer.poll_unpin(cx).is_ready() {
                self.ack_timer = None;
                return Poll::Ready(());
            }
        }

        Poll::Pending
    }
}

/// I2P virtual stream.
///
/// Implements a `Future` which returns the send stream ID after the virtual stream has been shut
/// down, either by the client or by the remote participant.
pub struct Stream<R: Runtime> {
    /// RX channel for receiving [`Packet`]s from the network.
    cmd_rx: Receiver<Vec<u8>>,

    /// Stream configuration.
    config: StreamConfig,

    /// TX channel for sending [`Packet`]s to the network.
    event_tx: Sender<(DestinationId, Vec<u8>)>,

    /// Inbound context for packets received from the network.
    inbound_context: InboundContext<R>,

    /// ID of the local destination.
    local: DestinationId,

    /// Next sequence number.
    next_seq_nro: u32,

    /// Read buffer.
    read_buffer: Vec<u8>,

    /// Socket state.
    read_state: SocketState,

    /// Receive stream ID (selected by remote peer).
    recv_stream_id: u32,

    /// ID of the remote destination.
    remote: DestinationId,

    /// Send stream ID (selected by us).
    send_stream_id: u32,

    /// Underlying TCP stream used to communicate with the client.
    stream: R::TcpStream,

    /// Write state.
    write_state: WriteState,
}

impl<R: Runtime> Stream<R> {
    /// Create new [`Stream`]
    pub fn new(
        stream: R::TcpStream,
        initial_message: Option<Vec<u8>>,
        context: StreamContext,
        config: StreamConfig,
        state: StreamKind,
    ) -> Self {
        let StreamContext {
            local,
            remote,
            cmd_rx,
            event_tx,
            recv_stream_id,
        } = context;

        let (send_stream_id, initial_message, highest_ack) = match state {
            StreamKind::Inbound { payload } => {
                let send_stream_id = R::rng().next_u32();
                let packet = PacketBuilder::new(send_stream_id)
                    .with_send_stream_id(recv_stream_id)
                    .with_seq_nro(0)
                    .with_synchronize()
                    .build();

                event_tx.try_send((remote.clone(), packet.to_vec())).unwrap();

                (
                    send_stream_id,
                    match (initial_message, payload.is_empty()) {
                        (Some(mut initial), false) => {
                            initial.extend_from_slice(&payload);
                            Some(initial)
                        }
                        (Some(initial), true) => Some(initial),
                        (None, false) => Some(payload),
                        (None, true) => None,
                    },
                    0u32,
                )
            }
            StreamKind::InboundPending {
                send_stream_id,
                seq_nro,
                packets,
            } => {
                let combined = packets.into_iter().fold(Vec::new(), |mut message, packet| {
                    message.extend_from_slice(&packet);
                    message
                });

                tracing::trace!(
                    target: LOG_TARGET,
                    %local,
                    %remote,
                    ?send_stream_id,
                    ?recv_stream_id,
                    pending_payload_len = ?combined.len(),
                    "initialize state from pending connection",
                );

                (
                    send_stream_id,
                    match (initial_message, combined.is_empty()) {
                        (None, true) => None,
                        (None, false) => Some(combined),
                        (Some(message), true) => Some(message),
                        (Some(mut message), false) => {
                            message.extend_from_slice(&combined);
                            Some(message)
                        }
                    },
                    seq_nro,
                )
            }
            StreamKind::Outbound { send_stream_id } => (
                send_stream_id,
                initial_message.is_some().then(|| b"STREAM STATUS RESULT=OK\n".to_vec()),
                0u32,
            ),
        };

        Self {
            cmd_rx,
            config,
            event_tx,
            inbound_context: InboundContext::new(highest_ack),
            local,
            next_seq_nro: 1u32,
            read_buffer: vec![0u8; READ_BUFFER_SIZE],
            read_state: SocketState::ReadMessage,
            recv_stream_id,
            remote,
            send_stream_id,
            stream,
            write_state: match initial_message {
                None => WriteState::GetMessage,
                Some(message) => WriteState::WriteMessage {
                    offset: 0usize,
                    message,
                },
            },
        }
    }

    /// Handle acknowledgements.
    fn handle_acks(&mut self, ack_through: u32, nacks: &[u32]) {}

    /// Handle `packet` received from the network.
    fn on_packet(&mut self, packet: Vec<u8>) -> Result<(), StreamingError> {
        let Packet {
            seq_nro,
            ack_through,
            nacks,
            resend_delay,
            flags,
            payload,
            ..
        } = Packet::parse(&packet).ok_or(StreamingError::Malformed)?;

        if flags.reset() {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                "stream reset",
            );

            return Err(StreamingError::Closed);
        }

        if flags.close() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.local,
                remote = %self.remote,
                recv_id = ?self.recv_stream_id,
                send_id = ?self.send_stream_id,
                "remote sent `CLOSE`",
            );
            self.inbound_context.close();
        }

        if !flags.no_ack() {
            self.handle_acks(ack_through, &nacks);
        }

        if !payload.is_empty() {
            self.inbound_context.handle_packet(seq_nro, payload.to_vec())?;
        }

        Ok(())
    }
}

impl<R: Runtime> Future for Stream<R> {
    type Output = u32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = Pin::into_inner(self);

        loop {
            match mem::replace(&mut this.write_state, WriteState::Poisoned) {
                WriteState::GetMessage => match this.cmd_rx.poll_recv(cx) {
                    Poll::Pending => match this.inbound_context.pop_message() {
                        None => {
                            this.write_state = WriteState::GetMessage;
                            break;
                        }
                        Some(message) =>
                            this.write_state = WriteState::WriteMessage {
                                offset: 0usize,
                                message,
                            },
                    },
                    Poll::Ready(None) => return Poll::Ready(this.recv_stream_id),
                    Poll::Ready(Some(message)) => match this.on_packet(message) {
                        Err(StreamingError::Closed | StreamingError::SequenceNumberTooHigh) =>
                            return Poll::Ready(this.recv_stream_id),
                        Err(error) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %this.local,
                                remote = %this.remote,
                                ?error,
                                "failed to handle packet"
                            );
                            this.write_state = WriteState::GetMessage;
                        }
                        Ok(()) => match this.inbound_context.pop_message() {
                            Some(message) =>
                                this.write_state = WriteState::WriteMessage {
                                    offset: 0usize,
                                    message,
                                },
                            None => this.write_state = WriteState::GetMessage,
                        },
                    },
                },
                WriteState::WriteMessage { offset, message } =>
                    match Pin::new(&mut this.stream).as_mut().poll_write(cx, &message[offset..]) {
                        Poll::Pending => {
                            this.write_state = WriteState::WriteMessage { offset, message };
                            break;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(this.recv_stream_id),
                        Poll::Ready(Ok(nwritten)) if nwritten == 0 => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                "wrote zero bytes to socket",
                            );

                            return Poll::Ready(this.recv_stream_id);
                        }
                        Poll::Ready(Ok(nwritten)) => match nwritten + offset == message.len() {
                            true => {
                                this.write_state = WriteState::GetMessage;
                            }
                            false => {
                                this.write_state = WriteState::WriteMessage {
                                    offset: offset + nwritten,
                                    message,
                                };
                            }
                        },
                    },
                WriteState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %this.local,
                        remote = %this.remote,
                        "write state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(this.recv_stream_id);
                }
            }
        }

        loop {
            match mem::replace(&mut this.read_state, SocketState::Poisoned) {
                SocketState::ReadMessage =>
                    match Pin::new(&mut this.stream).as_mut().poll_read(cx, &mut this.read_buffer) {
                        Poll::Pending => {
                            this.read_state = SocketState::ReadMessage;
                            break;
                        }
                        Poll::Ready(Err(error)) => {
                            tracing::debug!(
                                target: LOG_TARGET,
                                ?error,
                                local = %this.local,
                                remote = %this.remote,
                                "socket error",
                            );
                            return Poll::Ready(this.recv_stream_id);
                        }
                        Poll::Ready(Ok(nread)) => {
                            if nread == 0 {
                                tracing::debug!(
                                    target: LOG_TARGET,
                                    local = %this.local,
                                    remote = %this.remote,
                                    "read zero bytes from socket",
                                );
                                return Poll::Ready(this.recv_stream_id);
                            }

                            this.read_state = SocketState::SendMessage { offset: nread };
                        }
                    },
                SocketState::SendMessage { offset } => {
                    let seq_nro = {
                        let seq_nro = this.next_seq_nro;
                        this.next_seq_nro += 1;

                        seq_nro
                    };

                    tracing::info!(target: LOG_TARGET, "send next packet, seq nro = {seq_nro}");

                    let packet = PacketBuilder::new(this.send_stream_id)
                        .with_send_stream_id(this.recv_stream_id)
                        .with_seq_nro(seq_nro)
                        .with_payload(&this.read_buffer[..offset])
                        .build();

                    // TODO: retries
                    // TODO: cancel ack timer here if ok
                    if let Err(error) =
                        this.event_tx.try_send((this.remote.clone(), packet.to_vec()))
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %this.local,
                            remote = %this.remote,
                            ?error,
                            "failed to send packet",
                        );
                    }

                    this.read_state = SocketState::AwaitingAck {
                        seq_nro,
                        packet: packet.to_vec(),
                    };
                    break;
                }
                SocketState::AwaitingAck { seq_nro, packet } => {
                    this.read_state = SocketState::AwaitingAck { seq_nro, packet };
                    break;
                }
                SocketState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        local = %this.local,
                        remote = %this.remote,
                        "read state is poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(this.recv_stream_id);
                }
            }
        }

        // send plain ack
        if this.inbound_context.poll_unpin(cx).is_ready() {
            let ack_through = this.inbound_context.seq_nro;
            let nacks =
                this.inbound_context.missing.iter().copied().take(MAX_NACKS).collect::<Vec<_>>();

            let mut builder = PacketBuilder::new(this.send_stream_id)
                .with_send_stream_id(this.recv_stream_id)
                .with_ack_through(ack_through)
                .with_nacks(nacks)
                .with_seq_nro(PLAIN_ACK);

            builder = if this.inbound_context.missing.len() >= MAX_NACKS {
                builder.with_delay_requested(CHOKING_REQUEST)
            } else {
                builder
            };

            let packet = if this.inbound_context.can_close() {
                builder.with_close()
            } else {
                builder
            }
            .build()
            .to_vec();

            match this.event_tx.try_send((this.remote.clone(), packet.to_vec())) {
                Err(error) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        local = %this.local,
                        remote = %this.remote,
                        ?error,
                        "failed to send packet",
                    );
                    todo!();
                    // TODO: reset timer
                }
                Ok(()) => {
                    this.inbound_context.last_acked = ack_through;
                }
            }

            if this.inbound_context.can_close() {
                return Poll::Ready(this.recv_stream_id);
            }
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        mock::{MockRuntime, MockTcpStream},
        Runtime, TcpStream,
    };
    use rand::{
        distributions::{Alphanumeric, DistString},
        seq::SliceRandom,
        thread_rng, Rng,
    };
    use thingbuf::mpsc::channel;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    struct StreamBuilder {
        cmd_tx: Sender<Vec<u8>>,
        event_rx: Receiver<(DestinationId, Vec<u8>)>,
        stream: tokio::net::TcpStream,
    }

    impl StreamBuilder {
        pub async fn build_stream() -> (Stream<MockRuntime>, Self) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

            let address = listener.local_addr().unwrap();
            let (stream1, stream2) =
                tokio::join!(listener.accept(), MockTcpStream::connect(address));
            let (stream, _) = stream1.unwrap();

            let (event_tx, event_rx) = channel(64);
            let (cmd_tx, cmd_rx) = channel(64);

            (
                Stream::new(
                    stream2.unwrap(),
                    None,
                    StreamContext {
                        cmd_rx,
                        event_tx,
                        local: DestinationId::random(),
                        recv_stream_id: 1337u32,
                        remote: DestinationId::random(),
                    },
                    Default::default(),
                    StreamKind::Inbound { payload: vec![] },
                ),
                Self {
                    cmd_tx,
                    event_rx,
                    stream,
                },
            )
        }
    }

    #[tokio::test]
    async fn receive_multiple_packets() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        let messages = vec![
            b"hello\n".to_vec(),
            b"world\n".to_vec(),
            b"goodbye\n".to_vec(),
            b"world\n".to_vec(),
        ];

        for (i, message) in messages.iter().enumerate() {
            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(i as u32 + 1)
                        .with_payload(message)
                        .build()
                        .to_vec(),
                )
                .await;
        }

        let mut reader = BufReader::new(client);
        let mut response = String::new();

        for message in messages.into_iter() {
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(std::str::from_utf8(&message).unwrap(), response);
            response.clear();
        }

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        // all four messages acked with one packet
        {
            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 4u32);
            assert_eq!(seq_nro, 0u32);
            assert!(nacks.is_empty());
            assert!(payload.is_empty());
        }

        // send one more packet and verify that it's acked
        cmd_tx
            .send(
                PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(5u32)
                    .with_payload(b"test message\n")
                    .build()
                    .to_vec(),
            )
            .await;

        let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
            .await
            .expect("event")
            .expect("to succeed");

        let Packet {
            seq_nro,
            ack_through,
            nacks,
            payload,
            ..
        } = Packet::parse(&packet).unwrap();

        assert_eq!(ack_through, 5u32);
        assert_eq!(seq_nro, 0u32);
        assert!(nacks.is_empty());
        assert!(payload.is_empty());

        // read payload
        reader.read_line(&mut response).await.unwrap();
        assert_eq!("test message\n", response.as_str());
        response.clear();

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect_err("stream closed");
    }

    #[tokio::test]
    async fn out_of_order() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        let mut messages = VecDeque::from_iter([
            (4u32, b"message\n".to_vec()),
            (6u32, b"world\n".to_vec()),
            (2u32, b"world\n".to_vec()),
            (1u32, b"hello\n".to_vec()),
            (3u32, b"testing\n".to_vec()),
            (5u32, b"goodbye\n".to_vec()),
        ]);

        let mut reader = BufReader::new(client);
        let mut response = String::new();

        // send first packet and verify that there are nacks for packets 1, 2 and 3
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                )
                .await;

            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 4u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![1, 2, 3]);
            assert!(payload.is_empty());

            // verify the client is sent nothing
            assert!(tokio::time::timeout(
                Duration::from_millis(200),
                reader.read_line(&mut response)
            )
            .await
            .is_err());
        }

        // send second packet and verify that there is an additional nack for 5
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                )
                .await;

            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![1, 2, 3, 5]);
            assert!(payload.is_empty());

            // verify the client is sent nothing
            assert!(tokio::time::timeout(
                Duration::from_millis(200),
                reader.read_line(&mut response)
            )
            .await
            .is_err());
        }

        // send two more packets and verify that there is a nack left for packets 5 and 3
        // and that the client is send data for the first two packets
        {
            for _ in 0..2 {
                let (seq_nro, message) = messages.pop_front().unwrap();

                cmd_tx
                    .send(
                        PacketBuilder::new(1338u32)
                            .with_send_stream_id(1337u32)
                            .with_seq_nro(seq_nro)
                            .with_payload(&message)
                            .build()
                            .to_vec(),
                    )
                    .await;
            }

            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![3, 5]);
            assert!(payload.is_empty());

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "hello\n");

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "world\n");
        }

        // send the 3rd packet and verify there's still nack for packet 5
        // and that messages for packets 3 and 4 are returned to client
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                )
                .await;

            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![5]);
            assert!(payload.is_empty());

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "testing\n");

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "message\n");
        }

        // send 5th packet and verify that there are no more nacks
        // and that the payloads for packets 5 and 6 are returned
        {
            let (seq_nro, message) = messages.pop_front().unwrap();

            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                )
                .await;

            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("event")
                .expect("to succeed");

            let Packet {
                seq_nro,
                ack_through,
                nacks,
                payload,
                ..
            } = Packet::parse(&packet).unwrap();

            assert_eq!(ack_through, 6u32);
            assert_eq!(seq_nro, 0u32);
            assert_eq!(nacks, vec![]);
            assert!(payload.is_empty());

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "goodbye\n");

            response.clear();
            reader.read_line(&mut response).await.unwrap();
            assert_eq!(response.as_str(), "world\n");
        }

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect_err("stream closed");
    }

    #[tokio::test]
    async fn out_of_order_random() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        let test_string = Alphanumeric.sample_string(&mut thread_rng(), 256);

        let mut packets = test_string
            .clone()
            .into_bytes()
            .chunks(4)
            .enumerate()
            .map(|(seq_nro, message)| {
                PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(seq_nro as u32 + 1)
                    .with_payload(&message)
                    .build()
                    .to_vec()
            })
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 64);
        packets.shuffle(&mut thread_rng());

        // send packet to stream with random sleeps
        for packet in packets {
            cmd_tx.try_send(packet).unwrap();

            tokio::time::sleep(Duration::from_millis(thread_rng().gen_range(5..100))).await;
        }

        // ignore acks received from the stream
        tokio::spawn(async move { while let Some(_) = event_rx.recv().await {} });

        // read back response which is exactly 256 bytes long
        let mut response = [0u8; 256];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(std::str::from_utf8(&response).unwrap(), test_string);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect_err("stream closed");
    }

    #[tokio::test]
    async fn stream_reset() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // send two normal packets
        for (seq_nro, message) in vec![(1u32, b"msg1\n".to_vec()), (2u32, b"msg2\n".to_vec())] {
            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(seq_nro)
                        .with_payload(&message)
                        .build()
                        .to_vec(),
                )
                .await
                .unwrap();
        }

        // send packet with high seq number (missing packets) with `RESET`
        // and verify that the stream is closed event though there's missing data
        cmd_tx
            .send(
                PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(10u32)
                    .with_reset()
                    .build()
                    .to_vec(),
            )
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), handle).await.expect("no timeout");
    }

    #[tokio::test]
    async fn duplicate_packets() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        tokio::spawn(stream);

        let messages = vec![
            (1u32, b"hello1".to_vec()),
            (2u32, b"world1\n".to_vec()),
            (1u32, b"hello1\n".to_vec()),
            (4u32, b"world2\n".to_vec()),
            (3u32, b"goodbye2".to_vec()),
            (4u32, b"world3\n".to_vec()),
            (6u32, b"test2\n".to_vec()),
            (5u32, b"test1".to_vec()),
        ];

        for (i, message) in messages.iter() {
            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(*i)
                        .with_payload(message)
                        .build()
                        .to_vec(),
                )
                .await;
        }

        let mut reader = BufReader::new(client);
        let mut response = String::new();

        // 1st and 2nd messages are received normally
        {
            reader.read_line(&mut response).await.unwrap();
            assert_eq!("hello1world1\n", response);
            response.clear();
        }

        // 4th is send before 3rd but 3rd is ready normally
        {
            // concatenated 3rd and 4th message
            reader.read_line(&mut response).await.unwrap();
            assert_eq!("goodbye2world2\n", response);
            response.clear();
        }

        // 5th and 6th are received out of order and the duplicate 4th is ignored
        {
            // concatenated 5th and 6th message
            reader.read_line(&mut response).await.unwrap();
            assert_eq!("test1test2\n", response);
            response.clear();
        }
    }

    #[tokio::test]
    async fn out_of_order_last_packet_closes_connection() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: mut client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        // ignore syn packet
        let _ = event_rx.recv().await.unwrap();

        let test_string = Alphanumeric.sample_string(&mut thread_rng(), 128);

        let mut packets = test_string
            .clone()
            .into_bytes()
            .chunks(4)
            .enumerate()
            .map(|(seq_nro, message)| {
                let mut builder = PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(seq_nro as u32 + 1)
                    .with_payload(&message);

                if seq_nro == 31 {
                    builder.with_close()
                } else {
                    builder
                }
                .build()
                .to_vec()
            })
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 32);
        packets.shuffle(&mut thread_rng());

        // send packet to stream with random sleeps
        for packet in packets {
            cmd_tx.try_send(packet).unwrap();

            tokio::time::sleep(Duration::from_millis(thread_rng().gen_range(5..100))).await;
        }

        // read back response which is exactly 256 bytes long
        let mut response = [0u8; 128];
        client.read_exact(&mut response).await.unwrap();

        assert_eq!(std::str::from_utf8(&response).unwrap(), test_string);

        tokio::time::timeout(Duration::from_secs(5), handle).await.expect("no timeout");

        // ignore syn
        let (_, mut prev) = event_rx.recv().await.unwrap();

        // verify the last packet sent by the stream has the `CLOSE` flag set
        while let Ok((_, packet)) = event_rx.try_recv() {
            prev = packet;
        }

        let packet = Packet::parse(&prev).unwrap();
        assert!(packet.flags.close());
    }

    #[tokio::test]
    async fn sequence_number_too_high() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        let handle = tokio::spawn(stream);

        let messages = vec![
            b"hello\n".to_vec(),
            b"world\n".to_vec(),
            b"goodbye\n".to_vec(),
            b"world\n".to_vec(),
        ];

        for (i, message) in messages.iter().enumerate() {
            cmd_tx
                .send(
                    PacketBuilder::new(1338u32)
                        .with_send_stream_id(1337u32)
                        .with_seq_nro(i as u32 + 1)
                        .with_payload(message)
                        .build()
                        .to_vec(),
                )
                .await;
        }

        // send packet with way too high sequence number
        cmd_tx
            .send(
                PacketBuilder::new(1338u32)
                    .with_send_stream_id(1337u32)
                    .with_seq_nro(1024)
                    .with_payload(b"hello, world")
                    .build()
                    .to_vec(),
            )
            .await;

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stream to exist");
    }

    #[tokio::test]
    async fn choke() {
        let (
            stream,
            StreamBuilder {
                cmd_tx,
                stream: client,
                mut event_rx,
            },
        ) = StreamBuilder::build_stream().await;

        tokio::spawn(stream);

        // send every other packet so that the nack window grows
        for i in 0..1024 {
            if i % 2 == 0 {
                cmd_tx
                    .send(
                        PacketBuilder::new(1338u32)
                            .with_send_stream_id(1337u32)
                            .with_seq_nro(i as u32 + 1)
                            .with_payload(b"test")
                            .build()
                            .to_vec(),
                    )
                    .await;
            }
        }

        // ignore syn
        let _ = event_rx.recv().await.unwrap();

        // verify the last packet sent by the stream has the `CLOSE` flag set
        loop {
            let (_, packet) = tokio::time::timeout(Duration::from_secs(5), event_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed");
            let packet = Packet::parse(&packet).unwrap();

            if packet.flags.delay_requested() == Some(CHOKING_REQUEST) {
                break;
            }
        }
    }
}
