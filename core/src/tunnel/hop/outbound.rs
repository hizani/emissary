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
    i2np::HopRole,
    primitives::TunnelId,
    tunnel::hop::{Tunnel, TunnelDirection, TunnelHop},
};

use alloc::vec::Vec;
use core::{iter, num::NonZeroUsize};

/// Outbound tunnel.
#[derive(Debug)]
pub struct OutboundTunnel {
    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel hops.
    hops: Vec<TunnelHop>,
}

impl OutboundTunnel {
    /// Create new [`OutboundTunnel`].
    pub fn new(tunnel_id: TunnelId, hops: Vec<TunnelHop>) -> Self {
        Self { tunnel_id, hops }
    }

    // TODO: return future?
    pub fn send(&mut self) -> impl Iterator<Item = Vec<u8>> {
        // TODO: split input i2np message into fragments
        // TODO: encrypt fragments (tunnel delivery)
        // TODO: send fragments to next hop
        alloc::vec![].into_iter()
    }
}

impl Tunnel for OutboundTunnel {
    fn new(tunnel_id: TunnelId, hops: Vec<TunnelHop>) -> Self {
        OutboundTunnel::new(tunnel_id, hops)
    }

    fn hop_roles(num_hops: NonZeroUsize) -> impl Iterator<Item = HopRole> {
        match num_hops.get() == 1 {
            true => iter::once(HopRole::OutboundEndpoint).collect::<Vec<_>>().into_iter(),
            false => (0..num_hops.get() - 1)
                .map(|_| HopRole::Participant)
                .chain(iter::once(HopRole::OutboundEndpoint))
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }

    fn direction() -> TunnelDirection {
        TunnelDirection::Outbound
    }
}
