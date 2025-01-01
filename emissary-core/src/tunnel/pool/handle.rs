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
    error::ChannelError,
    i2np::Message,
    primitives::{Lease, RouterId, TunnelId},
    tunnel::pool::{TunnelMessage, TunnelPoolConfig},
};

use futures::Stream;
use futures_channel::oneshot;
use thingbuf::mpsc;

use alloc::vec::Vec;
use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Events emitted by a `TunnelPool`.
#[derive(Debug, Clone)]
pub enum TunnelPoolEvent {
    /// Tunnel pool has been shut down.
    TunnelPoolShutDown,

    /// Inbound tunnel has been built.
    InboundTunnelBuilt {
        /// Tunnel ID.
        tunnel_id: TunnelId,

        /// `Lease2` of the inbound tunnel.
        lease: Lease,
    },

    /// Outbound tunnel has been built.
    OutboundTunnelBuilt {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Inbound tunnel has been expired.
    InboundTunnelExpired {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Outbound tunnel has been expired.
    OutboundTunnelExpired {
        /// Tunnel ID.
        tunnel_id: TunnelId,
    },

    /// Message received into one of the inbound tunnels.
    Message {
        /// Received I2NP message.
        message: Message,
    },

    /// Dummy event.
    Dummy,
}

impl fmt::Display for TunnelPoolEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TunnelPoolShutDown => write!(f, "TunnelPoolEvent::TunnelPoolShutDown"),
            Self::InboundTunnelBuilt { .. } => write!(f, "TunnelPoolEvent::InboundTunnelBuilt"),
            Self::OutboundTunnelBuilt { .. } => write!(f, "TunnelPoolEvent::OutboundTunnelBuilt"),
            Self::InboundTunnelExpired { .. } => write!(f, "TunnelPoolEvent::InboundTunnelExpired"),
            Self::OutboundTunnelExpired { .. } =>
                write!(f, "TunnelPoolEvent::OutboundTunnelExpired"),
            Self::Message { .. } => write!(f, "TunnelPoolEvent::Message"),
            Self::Dummy => write!(f, "TunnelPoolEvent::Dummy"),
        }
    }
}

impl Default for TunnelPoolEvent {
    fn default() -> Self {
        Self::Dummy
    }
}

/// Tunnel sender.
pub trait TunnelSender: Clone {
    /// Send `message` to `router_id` via an outbound tunnel identified by `gateway`.
    ///
    /// Return an error if the channel is busy/closed.
    fn try_send_to_router(
        &self,
        gateway: TunnelId,
        router_id: RouterId,
        message: Vec<u8>,
    ) -> Result<(), ChannelError>;

    /// Send `message` via one of the `TunnelPool`'s outbound tunnels to remote tunnel
    /// identified by (`gateway`, `tunnel_id`) tuple.
    ///
    /// Return an error if the channel is busy/closed.
    fn try_send_to_tunnel(
        &self,
        gateway: RouterId,
        tunnel_id: TunnelId,
        message: Vec<u8>,
    ) -> Result<(), ChannelError>;

    /// Send `message` to `router_id` via an outbound tunnel identified by `gateway`.
    ///
    /// Blocks until the message is sent and returns an error if the channel is closed.
    fn send_to_router(
        &self,
        gateway: TunnelId,
        router_id: RouterId,
        message: Vec<u8>,
    ) -> impl Future<Output = Result<(), ChannelError>> + Send;

    /// Send `message` via one of the `TunnelPool`'s outbound tunnels to remote tunnel
    /// identified by (`gateway`, `tunnel_id`) tuple.
    ///
    /// Blocks until the message is sent and returns an error if the channel is closed.
    #[allow(unused)]
    fn send_to_tunnel(
        &self,
        gateway: RouterId,
        tunnel_id: TunnelId,
        message: Vec<u8>,
    ) -> impl Future<Output = Result<(), ChannelError>> + Send;
}

/// Tunnel message sender.
#[derive(Clone)]
struct TunnelMessageSender(mpsc::Sender<TunnelMessage>);

impl TunnelSender for TunnelMessageSender {
    fn try_send_to_router(
        &self,
        gateway: TunnelId,
        router_id: RouterId,
        message: Vec<u8>,
    ) -> Result<(), ChannelError> {
        self.0
            .try_send(TunnelMessage::RouterDelivery {
                gateway,
                router_id,
                message,
            })
            .map_err(From::from)
    }

    fn try_send_to_tunnel(
        &self,
        gateway: RouterId,
        tunnel_id: TunnelId,
        message: Vec<u8>,
    ) -> Result<(), ChannelError> {
        self.0
            .try_send(TunnelMessage::TunnelDelivery {
                gateway,
                tunnel_id,
                message,
            })
            .map_err(From::from)
    }

    fn send_to_router(
        &self,
        gateway: TunnelId,
        router_id: RouterId,
        message: Vec<u8>,
    ) -> impl Future<Output = Result<(), ChannelError>> {
        async move {
            self.0
                .send(TunnelMessage::RouterDelivery {
                    gateway,
                    router_id,
                    message,
                })
                .await
                .map_err(|_| ChannelError::Closed)
        }
    }

    fn send_to_tunnel(
        &self,
        gateway: RouterId,
        tunnel_id: TunnelId,
        message: Vec<u8>,
    ) -> impl Future<Output = Result<(), ChannelError>> {
        async move {
            self.0
                .send(TunnelMessage::TunnelDelivery {
                    gateway,
                    tunnel_id,
                    message,
                })
                .await
                .map_err(|_| ChannelError::Closed)
        }
    }
}

/// Tunnel pool handle.
///
/// Allows `Destination`s to communicate with their `TunnelPool`.
pub struct TunnelPoolHandle {
    /// Tunnel pool configuration.
    config: TunnelPoolConfig,

    /// RX channel for receiving events from `TunnelPool`.
    event_rx: mpsc::Receiver<TunnelPoolEvent>,

    /// Implementation of [`TunnelSender`].
    sender: TunnelMessageSender,

    /// TX channel for sending a shutdown command to `TunnelPool`.
    #[allow(unused)]
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl TunnelPoolHandle {
    /// Create new [`TunnelPoolHandle`].
    pub(super) fn new(
        config: TunnelPoolConfig,
        message_tx: mpsc::Sender<TunnelMessage>,
    ) -> (Self, mpsc::Sender<TunnelPoolEvent>, oneshot::Receiver<()>) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (event_tx, event_rx) = mpsc::channel(64);

        (
            Self {
                config,
                event_rx,
                sender: TunnelMessageSender(message_tx),
                shutdown_tx: Some(shutdown_tx),
            },
            event_tx,
            shutdown_rx,
        )
    }

    /// Send shutdown signal to `TunnelPool`.
    ///
    /// [`TunnelPoolEvent::TunnelPoolShutDown`] is emitted before `TunnelPool` is shut down.
    pub fn shutdown(&mut self) {
        self.shutdown_tx.take().map(|tx| tx.send(()));
    }

    /// Get reference to [`TunnelPoolConfig`] of the tunnel pool.
    pub fn config(&self) -> &TunnelPoolConfig {
        &self.config
    }

    /// Get reference to [`TunnelSender`].
    pub fn sender(&self) -> &impl TunnelSender {
        &self.sender
    }

    /// Create new [`TunnelPoolHandle`] for testing.
    #[cfg(test)]
    pub fn create() -> (
        Self,
        mpsc::Receiver<TunnelMessage>,
        mpsc::Sender<TunnelPoolEvent>,
        oneshot::Receiver<()>,
    ) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (event_tx, event_rx) = mpsc::channel(64);
        let (message_tx, message_rx) = mpsc::channel(64);

        (
            Self {
                config: Default::default(),
                event_rx,
                sender: TunnelMessageSender(message_tx),
                shutdown_tx: Some(shutdown_tx),
            },
            message_rx,
            event_tx,
            shutdown_rx,
        )
    }

    #[cfg(test)]
    /// Create new [`TunnelPoolHandle`] from `config`
    pub fn from_config(
        config: TunnelPoolConfig,
    ) -> (
        Self,
        mpsc::Receiver<TunnelMessage>,
        mpsc::Sender<TunnelPoolEvent>,
        oneshot::Receiver<()>,
    ) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (event_tx, event_rx) = mpsc::channel(64);
        let (message_tx, message_rx) = mpsc::channel(64);

        (
            Self {
                config,
                event_rx,
                sender: TunnelMessageSender(message_tx),
                shutdown_tx: Some(shutdown_tx),
            },
            message_rx,
            event_tx,
            shutdown_rx,
        )
    }
}

impl Stream for TunnelPoolHandle {
    type Item = TunnelPoolEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.event_rx.poll_recv(cx)
    }
}
