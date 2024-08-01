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
    i2np::HopRole,
    primitives::{MessageId, RouterId, TunnelId},
    tunnel::noise::{NoiseContext, PendingTunnelKeyContext},
};

use bytes::Bytes;

use alloc::{collections::VecDeque, vec::Vec};
use core::{iter, marker::PhantomData, num::NonZeroUsize};

pub mod inbound;
pub mod outbound;
pub mod pending;

/// Tunnel hop.
#[derive(Debug)]
pub struct TunnelHop {
    /// Hop role
    role: HopRole,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Key context.
    key_context: PendingTunnelKeyContext,
}

/// Tunnel direction.
#[derive(Debug)]
pub enum TunnelDirection {
    /// Inbound tunnel.
    Inbound,

    /// Outbound tunnel.
    Outbound,
}

/// Common interface for local tunnels (initiated by us).
pub trait Tunnel {
    /// Create new [`Tunnel`].
    fn new(tunnel_id: TunnelId, hops: Vec<TunnelHop>) -> Self;

    /// Get an iterator of hop roles for the tunnel participants.
    fn hop_roles(num_hops: NonZeroUsize) -> impl Iterator<Item = HopRole>;

    /// Get tunnel direction.
    fn direction() -> TunnelDirection;
}

pub struct TunnelBuilder<T: Tunnel> {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Hops.
    hops: VecDeque<TunnelHop>,

    /// Marker for `Tunnel`
    _tunnel: PhantomData<T>,
}

impl<T: Tunnel> TunnelBuilder<T> {
    /// Create new [`TunnelBuilder`].
    pub fn new(tunnel_id: TunnelId) -> Self {
        Self {
            tunnel_id,
            hops: VecDeque::new(),
            _tunnel: Default::default(),
        }
    }

    /// Push new hop into tunnel's hops.
    pub fn with_hop(mut self, hop: TunnelHop) -> Self {
        self.hops.push_back(hop);
        self
    }

    pub fn build(self) -> T {
        // TODO: reverse order based on tunnel direction?
        T::new(self.tunnel_id, self.hops.into_iter().collect())
    }
}

/// Tunnel build parameters.
pub struct TunnelBuildParameters {
    /// Tunnel hops.
    // TODO: introduce proper tunnel hop type?
    pub hops: Vec<(Bytes, StaticPublicKey)>,

    /// Noise context.
    pub noise: NoiseContext,

    /// Message ID used in the build message.
    pub message_id: MessageId,

    /// ID of the created endpoint/gateway.
    ///
    /// Tunnel creator (tunnel pool) selects the ID of the tunnel endpoint/gateway they
    /// created but rest of the hops will get assigned a random tunnel ID generated by
    /// [`InboundTunnel`]/[`OutboundTunnel`].
    pub tunnel_id: TunnelId,

    /// Local router hash.
    pub our_hash: Bytes,
}
