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
    crypto::{SigningPrivateKey, StaticPrivateKey},
    primitives::{
        router_address::TransportKind, Capabilities, Date, Mapping, RouterAddress, RouterIdentity,
        Str, LOG_TARGET,
    },
    runtime::Runtime,
    Config,
};

use hashbrown::HashMap;
use nom::{
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};
use rand_core::RngCore;

use alloc::{string::ToString, vec, vec::Vec};
use core::str::FromStr;

/// Router information
#[derive(Debug, Clone)]
pub struct RouterInfo {
    /// Router addresses.
    pub addresses: HashMap<TransportKind, RouterAddress>,

    /// Router capabilities.
    pub capabilities: Capabilities,

    /// Router identity.
    pub identity: RouterIdentity,

    /// Network ID.
    pub net_id: u8,

    /// Router options.
    pub options: HashMap<Str, Str>,

    /// When the router info was published.
    pub published: Date,
}

impl RouterInfo {
    pub fn new(now: u64, config: Config) -> Self {
        let Config {
            static_key,
            signing_key,
            ntcp2_config,
            caps,
            ..
        } = config;

        let identity =
            RouterIdentity::from_keys(static_key.clone(), signing_key).expect("to succeed");

        let ntcp2_config = ntcp2_config.unwrap();
        let ntcp2_port = ntcp2_config.port;
        let ntcp2_host = ntcp2_config.host;
        let ntcp2_key = ntcp2_config.key;
        let ntcp2_iv = ntcp2_config.iv;

        let ntcp2 = RouterAddress::new_published(ntcp2_key, ntcp2_iv, ntcp2_port, ntcp2_host);
        let net_id = Mapping::new(
            Str::from_str("netId").unwrap(),
            config
                .net_id
                .map_or_else(|| Str::from("2"), |value| Str::from(value.to_string())),
        );

        let caps = match caps {
            Some(caps) => Str::from(caps),
            None => match config.floodfill {
                true => Str::from("Xf"),
                false => Str::from("L"),
            },
        };

        let router_version = Mapping::new(
            Str::from_str("router.version").unwrap(),
            Str::from_str("0.9.62").unwrap(),
        );
        let caps_mapping = Mapping::new(Str::from("caps"), caps.clone());
        let options = Mapping::into_hashmap(vec![net_id, caps_mapping, router_version]);

        RouterInfo {
            addresses: HashMap::from_iter([(TransportKind::Ntcp2, ntcp2)]),
            capabilities: Capabilities::parse(&caps).expect("to succeed"),
            identity,
            net_id: config.net_id.unwrap_or(2),
            options,
            published: Date::new(now),
        }
    }

    fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterInfo> {
        let (rest, identity) = RouterIdentity::parse_frame(input.as_ref())?;
        let (rest, published) = Date::parse_frame(rest)?;
        let (mut rest, num_addresses) = be_u8(rest)?;
        let mut addresses = HashMap::<TransportKind, RouterAddress>::new();

        for _ in 0..num_addresses {
            let (_rest, address) = RouterAddress::parse_frame(rest)?;

            addresses.insert(*address.transport(), address);
            rest = _rest;
        }

        // ignore `peer_size`
        let (rest, _) = be_u8(rest)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;
        let options = Mapping::into_hashmap(options);

        let capabilities = match options.get(&Str::from("caps")) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "router capabilities missing",
                );
                return Err(Err::Error(make_error(input, ErrorKind::Fail)));
            }
            Some(caps) => match Capabilities::parse(&caps) {
                Some(caps) => caps,
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %caps,
                        "invalid capabilities",
                    );
                    return Err(Err::Error(make_error(input, ErrorKind::Fail)));
                }
            },
        };

        let net_id = match options.get(&Str::from("netId")) {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "network id not specified",
                );
                return Err(Err::Error(make_error(input, ErrorKind::Fail)));
            }
            Some(net_id) => match net_id.parse::<u8>() {
                Ok(net_id) => net_id,
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %net_id,
                        ?error,
                        "failed to parse net id",
                    );
                    return Err(Err::Error(make_error(input, ErrorKind::Fail)));
                }
            },
        };

        identity.signing_key().verify(input, rest).or_else(|error| {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                "invalid signature for router info",
            );
            Err(Err::Error(make_error(input, ErrorKind::Fail)))
        })?;

        Ok((
            rest,
            RouterInfo {
                identity,
                published,
                addresses,
                options,
                capabilities,
                net_id,
            },
        ))
    }

    // TODO: ugliest thing i've seen in my life
    pub fn serialize(&self, signing_key: &SigningPrivateKey) -> Vec<u8> {
        let identity = self.identity.serialize();
        let published = self.published.serialize();
        let ntcp2 = self.addresses.get(&TransportKind::Ntcp2).unwrap().serialize();
        let options = {
            let mut options = self.options.clone().into_iter().collect::<Vec<_>>();
            options.sort_by(|a, b| a.0.cmp(&b.0));

            options
                .into_iter()
                .map(|(key, value)| Mapping::new(key, value).serialize())
                .flatten()
                .collect::<Vec<_>>()
        };

        let size = identity.len() + published.len() + ntcp2.len() + options.len() + 4 + 64;
        let mut out = vec![0u8; size];

        out[..391].copy_from_slice(&identity);
        out[391..399].copy_from_slice(&published);
        out[399] = 1;
        out[400..400 + ntcp2.len()].copy_from_slice(&ntcp2);
        out[400 + ntcp2.len()] = 0;

        let mapping_size = (options.len() as u16).to_be_bytes().to_vec();
        out[400 + ntcp2.len() + 1..400 + ntcp2.len() + 3].copy_from_slice(&mapping_size);
        out[400 + ntcp2.len() + 3..400 + ntcp2.len() + 3 + options.len()].copy_from_slice(&options);

        let signature = signing_key.sign(&out[..size - 64]);
        out[400 + ntcp2.len() + 3 + options.len()..400 + ntcp2.len() + 3 + options.len() + 64]
            .copy_from_slice(&signature);

        out
    }

    /// Try to parse router information from `bytes`.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Option<Self> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Returns `true` if the router is a floodfill router.
    pub fn is_floodfill(&self) -> bool {
        self.capabilities.is_floodfill()
    }

    /// Returns `true` if the router is considered reachable.
    ///
    /// Router is considered reachable if its caps don't specify otherwise and it has at least one
    /// published address.
    pub fn is_reachable(&self) -> bool {
        // TODO: add ssu2 support
        self.capabilities.is_reachable()
            && self.addresses.get(&TransportKind::Ntcp2).map_or(false, |address| {
                address.options().get(&Str::from("host")).is_some()
                    && address.options().get(&Str::from("port")).is_some()
            })
    }

    /// Get network ID of the [`RouterInfo`].
    pub fn net_id(&self) -> u8 {
        self.net_id
    }
}

#[cfg(test)]
impl RouterInfo {
    /// Create new random [`RouterInfo`].
    pub fn random<R: Runtime>() -> Self {
        let static_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        let signing_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        Self::from_keys::<R>(static_key, signing_key)
    }

    /// Create new random [`RouterInfo`] and serialize it.
    pub fn random_with_keys<R: Runtime>() -> (Self, StaticPrivateKey, SigningPrivateKey) {
        let raw_static_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };
        let static_key = StaticPrivateKey::from(raw_static_key.clone());

        let raw_signing_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };
        let signing_key = SigningPrivateKey::new(&raw_signing_key).unwrap();

        (
            Self::from_keys::<R>(raw_static_key, raw_signing_key),
            static_key,
            signing_key,
        )
    }

    /// Create new random [`RouterInfo`] for a floodfill router.
    pub fn floodfill<R: Runtime>() -> Self {
        let static_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        let signing_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };

        let mut info = Self::from_keys::<R>(static_key, signing_key);
        info.options.insert(Str::from("caps"), Str::from("XfR"));
        info.options.insert(Str::from("netId"), Str::from("2"));
        info.capabilities = Capabilities::parse(&Str::from("XfR")).expect("to succeed");

        info
    }

    /// Create new random [`RouterInfo`] from static and signing keys.
    pub fn from_keys<R: Runtime>(static_key: Vec<u8>, signing_key: Vec<u8>) -> Self {
        let identity = RouterIdentity::from_keys(static_key, signing_key).expect("to succeed");

        let ntcp2_port = R::rng().next_u32() as u16;
        let ntcp2_host = format!(
            "{}.{}.{}.{}",
            {
                loop {
                    let address = R::rng().next_u32() % 256;

                    if address != 0 {
                        break address;
                    }
                }
            },
            R::rng().next_u32() % 256,
            R::rng().next_u32() % 256,
            R::rng().next_u32() % 256,
        );
        let ntcp2_key = {
            let mut key_bytes = vec![0u8; 32];
            R::rng().fill_bytes(&mut key_bytes);

            key_bytes
        };
        let ntcp2_iv = {
            let mut iv_bytes = [0u8; 16];
            R::rng().fill_bytes(&mut iv_bytes);

            iv_bytes
        };

        let ntcp2 = RouterAddress::new_published(ntcp2_key, ntcp2_iv, ntcp2_port, ntcp2_host);
        let net_id = Mapping::new(Str::from_str("netId").unwrap(), Str::from_str("2").unwrap());
        let caps = Mapping::new(Str::from_str("caps").unwrap(), Str::from_str("L").unwrap());
        let router_version = Mapping::new(
            Str::from_str("router.version").unwrap(),
            Str::from_str("0.9.62").unwrap(),
        );
        let options = Mapping::into_hashmap(vec![net_id, caps, router_version]);

        RouterInfo {
            addresses: HashMap::from_iter([(TransportKind::Ntcp2, ntcp2)]),
            capabilities: Capabilities::parse(&Str::from("L")).expect("to succeed"),
            identity,
            net_id: 2,
            options,
            published: Date::new(R::rng().next_u64()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;
    use std::{str::FromStr, time::Duration};

    #[test]
    fn parse_router_1() {
        let router_info_bytes = include_bytes!("../../test-vectors/router1.dat");
        let router_info = RouterInfo::parse(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost(),
            10
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("217.70.194.82").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("10994").unwrap())
        );

        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost(),
            14
        );
        assert!(router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options()
            .get(&Str::from_str("host").unwrap())
            .is_none());
        assert!(router_info
            .addresses
            .get(&TransportKind::Ntcp2)
            .unwrap()
            .options()
            .get(&Str::from_str("port").unwrap())
            .is_none());

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.42").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("LU").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_2() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");
        let router_info = RouterInfo::parse(router_info_bytes).unwrap();

        assert_eq!(router_info.addresses.len(), 2);

        // ssu
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ssu2).unwrap().cost(),
            10
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("68.202.112.209").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ssu2)
                .unwrap()
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("11331").unwrap())
        );

        // ntcp2
        assert_eq!(
            router_info.addresses.get(&TransportKind::Ntcp2).unwrap().cost(),
            3
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options()
                .get(&Str::from_str("host").unwrap()),
            Some(&Str::from_str("68.202.112.209").unwrap())
        );
        assert_eq!(
            router_info
                .addresses
                .get(&TransportKind::Ntcp2)
                .unwrap()
                .options()
                .get(&Str::from_str("port").unwrap()),
            Some(&Str::from_str("11331").unwrap())
        );

        // options
        assert_eq!(
            router_info.options.get(&Str::from_str("router.version").unwrap()),
            Some(&Str::from_str("0.9.46").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("caps").unwrap()),
            Some(&Str::from_str("LR").unwrap())
        );
        assert_eq!(
            router_info.options.get(&Str::from_str("netId").unwrap()),
            Some(&Str::from_str("2").unwrap())
        );
    }

    #[test]
    fn parse_router_3() {
        let router_info_bytes = include_bytes!("../../test-vectors/router3.dat");
        assert!(RouterInfo::parse(router_info_bytes).is_none());
    }

    #[test]
    fn is_not_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router2.dat");

        assert!(!RouterInfo::parse(router_info_bytes).unwrap().is_floodfill())
    }

    #[test]
    fn is_floodfill() {
        let router_info_bytes = include_bytes!("../../test-vectors/router4.dat");

        assert!(RouterInfo::parse(router_info_bytes).unwrap().is_floodfill())
    }

    #[test]
    fn net_id_missing() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published(
                    vec![1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".to_string(),
                ),
            )]),
            options: HashMap::from_iter([(Str::from("caps"), Str::from("L"))]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).is_none());
    }

    #[test]
    fn caps_missing() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published(
                    vec![1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".to_string(),
                ),
            )]),
            options: HashMap::from_iter([(Str::from("netId"), Str::from("2"))]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("L")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).is_none());
    }

    #[test]
    fn hidden_router_not_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published(
                    vec![1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".to_string(),
                ),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("HL")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("HL")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn unreachable_router_not_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published(
                    vec![1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".to_string(),
                ),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("UL")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("UL")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn reachable_but_no_published_address() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_unpublished(vec![1u8; 32]),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(!RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    #[test]
    fn reachable_explicitly_specified() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published(
                    vec![1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".to_string(),
                ),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("LR")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("LR")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }

    // router doesn't explicitly specify the `R` flag
    #[test]
    fn maybe_reachable() {
        let (identity, _sk, sgk) = RouterIdentity::random();

        let serialized = RouterInfo {
            identity,
            published: Date::new(
                (MockRuntime::time_since_epoch() - Duration::from_secs(60)).as_millis() as u64,
            ),
            addresses: HashMap::from_iter([(
                TransportKind::Ntcp2,
                RouterAddress::new_published(
                    vec![1u8; 32],
                    [2u8; 16],
                    8888,
                    "127.0.0.1".to_string(),
                ),
            )]),
            options: HashMap::from_iter([
                (Str::from("netId"), Str::from("2")),
                (Str::from("caps"), Str::from("Xf")),
            ]),
            net_id: 2,
            capabilities: Capabilities::parse(&Str::from("Xf")).unwrap(),
        }
        .serialize(&sgk);

        assert!(RouterInfo::parse(&serialized).unwrap().is_reachable());
    }
}
