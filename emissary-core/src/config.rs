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

use core::net::Ipv4Addr;

use crate::{primitives::Str, profile::Profile, tunnel::TunnelPoolConfig};

use alloc::{string::String, vec::Vec};

/// Exploratory tunnel pool config.
#[derive(Clone, PartialEq, Eq)]
pub struct ExploratoryConfig {
    /// Length of an inbound exploratory tunnel.
    pub inbound_len: Option<usize>,

    /// Number of inbound exploratory tunnels.
    pub inbound_count: Option<usize>,

    /// Length of an outbound exploratory tunnel.
    pub outbound_len: Option<usize>,

    /// Number of outbound exploratory tunnels.
    pub outbound_count: Option<usize>,
}

impl From<Option<ExploratoryConfig>> for TunnelPoolConfig {
    fn from(value: Option<ExploratoryConfig>) -> Self {
        let default_config = TunnelPoolConfig::default();

        match value {
            None => default_config,
            Some(config) => TunnelPoolConfig {
                name: Str::from("exploratory"),
                num_inbound: config.inbound_count.unwrap_or(default_config.num_inbound),
                num_inbound_hops: config.inbound_len.unwrap_or(default_config.num_inbound_hops),
                num_outbound: config.outbound_count.unwrap_or(default_config.num_outbound),
                num_outbound_hops: config.outbound_len.unwrap_or(default_config.num_outbound_hops),
            },
        }
    }
}

/// NTCP2 configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Ntcp2Config {
    /// NTCP2 port.
    pub port: u16,

    /// NTCP2 listen address.
    pub host: Option<Ipv4Addr>,

    /// Should NTCP2 be published in router info.
    pub published: bool,

    /// NTCP2 key.
    pub key: [u8; 32],

    /// NTCP2 IV.
    pub iv: [u8; 16],
}

/// I2CP configuration.
#[derive(Debug, Clone)]
pub struct I2cpConfig {
    /// I2CP server listen port.
    pub port: u16,
}

/// SAMv3 configuration.
#[derive(Debug, Clone)]
pub struct SamConfig {
    /// SAMv3 TCP server listen port.
    pub tcp_port: u16,

    /// SAMv3 UDP server listen port.
    pub udp_port: u16,

    /// Host where the sockets shoud be bound to.
    pub host: String,
}

/// Metrics configuration.
#[derive(Default, Debug, Clone)]
pub struct MetricsConfig {
    /// Disable metrics server.
    pub disable_metrics: bool,

    /// Port where the metrics server should be bound to.
    pub metrics_server_port: Option<u16>,
}

/// Router configuration.
#[derive(Default)]
pub struct Config {
    /// Allow local addresses.
    pub allow_local: bool,

    /// Router capabilities.
    pub caps: Option<String>,

    /// Exploratory tunnel pool config.
    pub exploratory: Option<ExploratoryConfig>,

    /// Should the node be run as a floodfill router.
    pub floodfill: bool,

    /// I2CP configuration.
    ///
    /// `None` if I2CP is disabled.
    pub i2cp_config: Option<I2cpConfig>,

    /// Are tunnels allowed to be insecure.
    pub insecure_tunnels: bool,

    /// Metrics configuration.
    pub metrics: MetricsConfig,

    /// Network ID.
    pub net_id: Option<u8>,

    /// NTCP2 configuration.
    pub ntcp2_config: Option<Ntcp2Config>,

    /// Known router profiles.
    pub profiles: Vec<(String, Profile)>,

    /// Router Info, if it exists.
    pub router_info: Option<Vec<u8>>,

    /// Known routers.
    pub routers: Vec<Vec<u8>>,

    /// SAMv3 configuration.
    ///
    /// `None` if SAMv3 is disabled.
    pub samv3_config: Option<SamConfig>,

    /// Router signing key.
    pub signing_key: Option<[u8; 32]>,

    /// Router static key.
    pub static_key: Option<[u8; 32]>,
}
