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

//! Noise implementation for ECIES tunnels.
//!
//! https://geti2p.net/spec/tunnel-creation-ecies
//!
//! Implementation refers to `ck` as `chaining_key` and to `h` as `state`.

use crate::{
    crypto::{
        aes::{cbc, ecb},
        base64_encode,
        chachapoly::{ChaCha, ChaChaPoly},
        hmac::Hmac,
        sha256::Sha256,
        EphemeralPrivateKey, EphemeralPublicKey, StaticPrivateKey, StaticPublicKey,
    },
    error::TunnelError,
    i2np::{
        tunnel::build::variable, DeliveryInstruction, DeliveryInstructions, EncryptedTunnelData,
        GarlicClove, GarlicMessage, GarlicMessageBlock, GarlicMessageType, HopRole, MessageKind,
        MessageType, OutboundTunnelBuildReply, OwnedDeliveryInstruction, MessageBuilder,
        Message, ShortTunnelBuildRecord, ShortTunnelBuildRecordBuilder,
        ShortTunnelBuildRequestBuilder, TunnelData, TunnelGateway, I2NP_SHORT,
        I2NP_STANDARD,
    },
    primitives::{RouterId, RouterInfo, TunnelId},
    runtime::Runtime,
    tunnel::LOG_TARGET,
    Error,
};

use bytes::Bytes;
use hashbrown::HashMap;
use rand_core::RngCore;
use zeroize::Zeroize;

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{fmt, ops::Deref, time::Duration};

/// Noise protocol name;.
const PROTOCOL_NAME: &str = "Noise_N_25519_ChaChaPoly_SHA256";

struct TunnelHop {
    /// Tunnel hop kind.
    role: HopRole,

    /// Tunnel ID.
    ///
    /// Assigned by the tunnel creator to us.
    tunnel_id: u32,

    /// Next tunnel ID.
    ///
    /// Assigned by the tunnel creator to the next hop.
    next_tunnel_id: u32,

    /// Next router ID.
    next_router_id: RouterId,

    /// Layer key.
    ///
    /// TODO: docs
    layer_key: Vec<u8>,

    /// IV key.
    ///
    /// TODO: docs
    iv_key: Vec<u8>,

    /// I2NP message fragments.
    //
    // TODO: easily dossable, add expiration
    fragments: HashMap<u32, FragmentedMessage>,
}

struct TunnelHopNew {
    role: HopRole,
    tunnel_id: u32,
    index: usize,
    next_tunnel_id: u32,
    next_router_id: RouterId,
    layer_key: Vec<u8>,
    iv_key: Vec<u8>,
    garlic_key: Vec<u8>,
    garlic_tag: Vec<u8>,
    reply_key: Vec<u8>,
    state: Vec<u8>,
}

struct PendingTunnel {
    inbound: bool,
    hops: VecDeque<(u32, TunnelHopNew)>,
}

impl fmt::Debug for TunnelHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelHop")
            .field("role", &self.role)
            .field("tunnel_id", &self.tunnel_id)
            .field("next_tunnel_id", &self.next_tunnel_id)
            .field("next_router_id", &self.next_router_id)
            .finish_non_exhaustive()
    }
}

struct FragmentedMessage {
    first_fragment: Vec<u8>,
    delivery_instructions: OwnedDeliveryInstruction,
    middle_fragments: BTreeMap<usize, Vec<u8>>,
    last_fragment: Option<Vec<u8>>,
}

/// Noise context for tunnels.
#[derive(Clone)]
pub struct NoiseContext {
    /// Chaining key.
    chaining_key: Bytes,

    /// Inbound state.
    inbound_state: Bytes,

    /// Outbound state.
    outbound_state: Bytes,

    /// Local static key.
    local_key: Arc<StaticPrivateKey>,

    /// Local router hash.
    local_router_hash: Bytes,
}

pub struct TunnelKeyContext {
    iv_key: Vec<u8>,
    layer_key: Vec<u8>,
}

impl TunnelKeyContext {
    /// Get reference to IV key.
    pub fn iv_key(&self) -> &[u8] {
        &self.iv_key
    }

    /// Get reference to layer key.
    pub fn layer_key(&self) -> &[u8] {
        &self.layer_key
    }
}

pub struct PendingTunnelKeyContext {
    pub garlic_key: Option<Vec<u8>>,
    pub garlic_tag: Option<Vec<u8>>,
    pub iv_key: Vec<u8>,
    pub layer_key: Vec<u8>,
    pub local_ephemeral: Vec<u8>,
    pub reply_key: Vec<u8>,
    pub state: Vec<u8>,
    pub chacha: Vec<u8>,
}

impl fmt::Debug for PendingTunnelKeyContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTunnelKeyContext").finish_non_exhaustive()
    }
}

pub struct PendingTunnelSession {
    /// Chaining key.
    chaining_key: Vec<u8>,

    /// ChaCha20Poly1305 key for decrypting the build request record.
    aead_key: Vec<u8>,

    /// AEAD state.
    state: Vec<u8>,
}

impl PendingTunnelSession {
    /// Create new [`PendingTunnelSession`].
    fn new(chaining_key: Vec<u8>, aead_key: Vec<u8>, state: Vec<u8>) -> Self {
        Self {
            chaining_key,
            aead_key,
            state,
        }
    }

    // TODO: ugly
    pub fn decrypt_build_record(
        &mut self,
        mut record: Vec<u8>,
    ) -> crate::Result<(Vec<u8>, Vec<u8>)> {
        let state = Sha256::new().update(&self.state).update(&record).finalize();

        ChaChaPoly::new(&self.aead_key).decrypt_with_ad(&self.state, &mut record)?;

        Ok((record, state))
    }

    /// Derive tunnel key context for an inbound session.
    pub fn derive_tunnel_keys(mut self, role: HopRole) -> PendingTunnelKeyContext {
        let mut temp_key = Hmac::new(&self.chaining_key).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelReplyKey").update(&[0x01]).finalize();
        let reply_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelReplyKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let mut ck = Hmac::new(&temp_key).update(&b"SMTunnelLayerKey").update(&[0x01]).finalize();
        let layer_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelLayerKey")
            .update(&[0x02])
            .finalize();

        match role {
            HopRole::InboundGateway | HopRole::Participant => {
                ck.zeroize();
                temp_key.zeroize();
                self.chaining_key.zeroize();

                PendingTunnelKeyContext {
                    chacha: Vec::new(),
                    garlic_key: None,
                    garlic_tag: None,
                    iv_key: ck,
                    layer_key,
                    local_ephemeral: Vec::new(),
                    reply_key,
                    state: Vec::new(),
                }
            }
            HopRole::OutboundEndpoint => {
                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let ck =
                    Hmac::new(&temp_key).update(&b"TunnelLayerIVKey").update(&[0x01]).finalize();
                let iv_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"TunnelLayerIVKey")
                    .update(&[0x02])
                    .finalize();

                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let mut ck =
                    Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
                let garlic_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"RGarlicKeyAndTag")
                    .update(&[0x02])
                    .finalize();

                let garlic_tag = ck[..8].to_vec();

                ck.zeroize();
                temp_key.zeroize();
                self.chaining_key.zeroize();

                PendingTunnelKeyContext {
                    chacha: Vec::new(),
                    garlic_key: Some(garlic_key),
                    garlic_tag: Some(garlic_tag),
                    iv_key,
                    layer_key,
                    local_ephemeral: Vec::new(),
                    reply_key,
                    state: Vec::new(),
                }
            }
        }
    }
}

impl NoiseContext {
    /// Create new [`NoiseContext`].
    pub fn new(local_key: StaticPrivateKey, local_router_hash: Bytes) -> Self {
        let chaining_key = {
            let mut chaining_key = PROTOCOL_NAME.as_bytes().to_vec();
            chaining_key.append(&mut vec![0u8]);
            chaining_key
        };
        let outbound_state = Sha256::new().update(&chaining_key).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(local_key.public().to_bytes())
            .finalize();

        Self {
            local_router_hash,
            chaining_key: Bytes::from(chaining_key),
            inbound_state: Bytes::from(inbound_state),
            outbound_state: Bytes::from(outbound_state),
            local_key: Arc::new(local_key),
        }
    }

    /// Get reference to local router hash.
    pub fn local_router_hash(&self) -> &Bytes {
        &self.local_router_hash
    }

    /// Derive chaining and Chacha20Poly1305 keys for an inbound session.
    //
    // TODO: wrong key type!
    // TODO: remove
    pub fn derive_inbound_keys(
        &self,
        remote_ephemeral: StaticPublicKey,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut shared_secret = self.local_key.diffie_hellman(&remote_ephemeral);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();
        let state = Sha256::new()
            .update(&self.inbound_state)
            .update(&remote_ephemeral.to_bytes())
            .finalize();

        temp_key.zeroize();
        shared_secret.zeroize();

        (chaining_key, aead_key, state)
    }

    /// Create
    //
    // TODO: wrong key type!
    // TODO: rename
    pub fn create_pending_tunnel_session(
        &mut self,
        remote_ephemeral: StaticPublicKey,
    ) -> PendingTunnelSession {
        let mut shared_secret = self.local_key.diffie_hellman(&remote_ephemeral);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();
        let state = Sha256::new()
            .update(&self.inbound_state)
            .update(&remote_ephemeral.to_bytes())
            .finalize();

        temp_key.zeroize();
        shared_secret.zeroize();

        PendingTunnelSession::new(chaining_key, aead_key, state)
    }

    /// Derive chaining and Chacha20Poly1305 keys for an outbound session.
    fn derive_outbound_keys(
        &self,
        remote_static: StaticPublicKey,
        local_ephemeral: EphemeralPrivateKey,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut shared_secret = local_ephemeral.diffie_hellman(&remote_static);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();

        temp_key.zeroize();
        shared_secret.zeroize();
        local_ephemeral.zeroize();

        (chaining_key, aead_key)
    }

    /// Derive tunnel key context for an outbound session.
    pub fn derive_outbound_tunnel_keys<R: Runtime>(
        &self,
        remote_static: StaticPublicKey,
        role: HopRole,
    ) -> PendingTunnelKeyContext {
        let local_ephemeral = EphemeralPrivateKey::new(R::rng());
        let local_ephemeral_public = local_ephemeral.public_key().to_vec();
        let state = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update::<&[u8]>(remote_static.as_ref())
                .finalize();

            Sha256::new().update(&state).update(&local_ephemeral_public).finalize()
        };
        let (mut chaining_key, aead_key) =
            self.derive_outbound_keys(remote_static, local_ephemeral);

        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelReplyKey").update(&[0x01]).finalize();
        let reply_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelReplyKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let mut ck = Hmac::new(&temp_key).update(&b"SMTunnelLayerKey").update(&[0x01]).finalize();
        let layer_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelLayerKey")
            .update(&[0x02])
            .finalize();

        match role {
            HopRole::InboundGateway | HopRole::Participant => {
                ck.zeroize();
                temp_key.zeroize();
                chaining_key.zeroize();

                PendingTunnelKeyContext {
                    chacha: aead_key,
                    garlic_key: None,
                    garlic_tag: None,
                    iv_key: ck,
                    layer_key,
                    local_ephemeral: local_ephemeral_public,
                    reply_key,
                    state,
                }
            }
            HopRole::OutboundEndpoint => {
                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let ck =
                    Hmac::new(&temp_key).update(&b"TunnelLayerIVKey").update(&[0x01]).finalize();
                let iv_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"TunnelLayerIVKey")
                    .update(&[0x02])
                    .finalize();

                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let mut ck =
                    Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
                let garlic_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"RGarlicKeyAndTag")
                    .update(&[0x02])
                    .finalize();

                let garlic_tag = ck[..8].to_vec();

                ck.zeroize();
                temp_key.zeroize();
                chaining_key.zeroize();

                PendingTunnelKeyContext {
                    chacha: aead_key,
                    garlic_key: Some(garlic_key),
                    garlic_tag: Some(garlic_tag),
                    iv_key,
                    layer_key,
                    local_ephemeral: local_ephemeral_public,
                    reply_key,
                    state,
                }
            }
        }
    }

    /// Derive tunnel key context for an inbound session.
    //
    // TODO: why does this take `Runtime`?
    pub fn derive_inbound_tunnel_keys<R: Runtime>(
        &self,
        mut chaining_key: Vec<u8>,
        role: HopRole,
    ) -> PendingTunnelKeyContext {
        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelReplyKey").update(&[0x01]).finalize();
        let reply_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelReplyKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let mut ck = Hmac::new(&temp_key).update(&b"SMTunnelLayerKey").update(&[0x01]).finalize();
        let layer_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelLayerKey")
            .update(&[0x02])
            .finalize();

        match role {
            HopRole::InboundGateway | HopRole::Participant => {
                ck.zeroize();
                temp_key.zeroize();
                chaining_key.zeroize();

                PendingTunnelKeyContext {
                    chacha: Vec::new(),
                    garlic_key: None,
                    garlic_tag: None,
                    iv_key: ck,
                    layer_key,
                    local_ephemeral: Vec::new(),
                    reply_key,
                    state: Vec::new(),
                }
            }
            HopRole::OutboundEndpoint => {
                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let ck =
                    Hmac::new(&temp_key).update(&b"TunnelLayerIVKey").update(&[0x01]).finalize();
                let iv_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"TunnelLayerIVKey")
                    .update(&[0x02])
                    .finalize();

                let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
                let mut ck =
                    Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
                let garlic_key = Hmac::new(&temp_key)
                    .update(&ck)
                    .update(&b"RGarlicKeyAndTag")
                    .update(&[0x02])
                    .finalize();

                let garlic_tag = ck[..8].to_vec();

                ck.zeroize();
                temp_key.zeroize();
                chaining_key.zeroize();

                PendingTunnelKeyContext {
                    chacha: Vec::new(),
                    garlic_key: Some(garlic_key),
                    garlic_tag: Some(garlic_tag),
                    iv_key,
                    layer_key,
                    local_ephemeral: Vec::new(),
                    reply_key,
                    state: Vec::new(),
                }
            }
        }
    }
}

/// Noise key context.
pub struct Noise {
    /// Chaining key.
    chaining_key: Vec<u8>,

    /// Inbound state.
    inbound_state: Vec<u8>,

    /// Local static key.
    local_key: StaticPrivateKey,

    /// Outbound state.
    outbound_state: Vec<u8>,

    /// Tunnel hops.
    tunnels: HashMap<TunnelId, TunnelHop>,

    pending_tunnels: HashMap<u32, PendingTunnel>,
    pending_messages: HashMap<u32, u32>,

    /// Random bytes used for tunnel data padding.
    padding_bytes: [u8; 1028],
}

impl Noise {
    /// Create new [`Noise`].
    ///
    /// https://geti2p.net/spec/tunnel-creation-ecies#kdf-for-initial-ck-and-h
    pub fn new<R: Runtime>(local_key: StaticPrivateKey) -> Self {
        let chaining_key = {
            let mut chaining_key = PROTOCOL_NAME.as_bytes().to_vec();
            chaining_key.append(&mut vec![0u8]);
            chaining_key
        };
        let outbound_state = Sha256::new().update(&chaining_key).finalize();
        let inbound_state = Sha256::new()
            .update(&outbound_state)
            .update(local_key.public().to_bytes())
            .finalize();

        // generate random padding bytes used in `TunnelData` messages
        let padding_bytes = {
            let mut padding_bytes = [0u8; 1028];
            R::rng().fill_bytes(&mut padding_bytes);

            padding_bytes = TryInto::<[u8; 1028]>::try_into(
                padding_bytes
                    .into_iter()
                    .map(|byte| if byte == 0 { 1u8 } else { byte })
                    .collect::<Vec<_>>(),
            )
            .expect("to succeed");

            padding_bytes
        };

        Self {
            chaining_key,
            inbound_state,
            local_key,
            outbound_state,
            tunnels: HashMap::new(),
            pending_tunnels: HashMap::new(),
            padding_bytes,
            pending_messages: HashMap::new(),
        }
    }

    // MixKey(DH())
    fn derive_keys(&self, ephemeral_key: StaticPublicKey) -> (Vec<u8>, Vec<u8>) {
        let mut shared_secret = self.local_key.diffie_hellman(&ephemeral_key);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();

        temp_key.zeroize();
        shared_secret.zeroize();

        (chaining_key, aead_key)
    }

    /// TODO: explain
    ///
    /// TODO: return `TunnelHop`?
    ///
    /// TODO: lot of refactoring needed
    ///
    /// https://geti2p.net/spec/tunnel-creation-ecies#kdf-for-request-record
    pub fn create_tunnel_hop(
        &mut self,
        truncated: &Vec<u8>,
        mut payload: Vec<u8>,
    ) -> Option<(Vec<u8>, RouterId, u32, MessageType)> {
        tracing::trace!(
            "payload len = {}, num records = {}",
            payload.len(),
            payload[0]
        );

        assert!(
            payload[1..].len() % 528 == 0,
            "invalid variable tunnel build message"
        );

        // TODO: better abstraction
        let mut record = payload[1..].chunks_mut(528).find(|chunk| &chunk[..16] == truncated)?;

        // TODO: no unwraps
        let state = Sha256::new().update(&self.inbound_state).update(&record[16..48]).finalize();
        let (chaining_key, aead_key) =
            self.derive_keys(StaticPublicKey::from_bytes(record[16..48].to_vec()).unwrap());
        let new_state = Sha256::new().update(&state).update(&record[48..]).finalize();

        let mut test = record[48..528].to_vec();
        ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

        let (next_router, message_id, message_type) = {
            let record = variable::TunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps

            let layer_key = record.tunnel_layer_key().to_vec();
            let iv_key = record.tunnel_iv_key().to_vec();

            tracing::trace!(
                target: LOG_TARGET,
                role = ?record.role(),
                tunnel_id = ?record.tunnel_id(),
                next_tunnel_id = ?record.next_tunnel_id(),
                next_message_id = record.next_message_id(),
                "VARIABLE TUNNEL BUILT",
            );

            let hop = TunnelHop {
                role: record.role(),
                tunnel_id: *record.tunnel_id(),
                next_tunnel_id: *record.next_tunnel_id(),
                next_router_id: record.next_router(),
                layer_key,
                iv_key,
                fragments: HashMap::new(),
            };
            self.tunnels.insert(TunnelId::from(record.tunnel_id()), hop);

            ((
                record.next_router(),
                record.next_message_id(),
                match record.role() {
                    HopRole::OutboundEndpoint => MessageType::VariableTunnelBuildReply,
                    _ => todo!(),
                },
            ))
        };

        record[48] = 0x00; // no options
        record[49] = 0x00;
        record[511] = 0x00; // accept

        // TODO: needs to encrypt with aes?

        let tag = ChaChaPoly::new(&chaining_key)
            .encrypt_with_ad(&new_state, &mut record[0..512])
            .unwrap();
        record[512..528].copy_from_slice(&tag);

        Some((payload, next_router, message_id, message_type))
    }

    // MixKey(DH())
    fn derive_keys_remote(
        &self,
        remote_key: &StaticPublicKey,
        mut local_key: EphemeralPrivateKey,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut shared_secret = local_key.diffie_hellman(&remote_key);
        let mut temp_key = Hmac::new(&self.chaining_key).update(&shared_secret).finalize();
        let chaining_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
        let aead_key = Hmac::new(&temp_key).update(&chaining_key).update(&[0x02]).finalize();

        temp_key.zeroize();
        shared_secret.zeroize();
        local_key.zeroize();

        (chaining_key, aead_key)
    }

    fn derive_tunnel_keys(
        &self,
        chaining_key: Vec<u8>,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelReplyKey").update(&[0x01]).finalize();
        let reply_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelReplyKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelLayerKey").update(&[0x01]).finalize();
        let layer_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelLayerKey")
            .update(&[0x02])
            .finalize();

        let else_key = ck.clone();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"TunnelLayerIVKey").update(&[0x01]).finalize();
        let iv_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"TunnelLayerIVKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
        let garlic_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"RGarlicKeyAndTag")
            .update(&[0x02])
            .finalize();

        let test = ck.iter().chain(garlic_key.iter()).collect::<Vec<_>>();
        tracing::error!("garlic key state: {test:?}");

        let garlic_tag = ck[..8].to_vec();

        (
            reply_key, layer_key, iv_key, else_key, garlic_key, garlic_tag,
        )
    }

    pub fn create_short_tunnel_build_request_outbound<R: Runtime>(
        &mut self,
        hops: Vec<RouterInfo>,
        our_hash: Vec<u8>,
    ) -> (u32, RouterId, Vec<u8>) {
        assert!(hops.len() == 2);

        let first_tunnel_id = R::rng().next_u32();
        let second_tunnel_id = R::rng().next_u32();
        let recv_tunnel_id = R::rng().next_u32();
        let message_id = R::rng().next_u32();
        let time_now = R::time_since_epoch().as_secs() as u32;
        let expiration = (R::time_since_epoch() + Duration::from_secs(180)).as_secs() as u32;

        tracing::info!("tunnels: {first_tunnel_id} -> {second_tunnel_id} -> {recv_tunnel_id}");
        tracing::info!("message id = {message_id}");

        // first record
        let mut record1 = ShortTunnelBuildRecordBuilder::default()
            .with_tunnel_id(first_tunnel_id)
            .with_next_tunnel_id(second_tunnel_id)
            .with_next_router_hash(hops[1].identity().hash().as_ref())
            .with_role(HopRole::Participant)
            .with_request_time(time_now)
            .with_request_expiration(expiration)
            .with_next_message_id(message_id) // TODO: different for every message?
            .serialize();

        // second record
        let mut record2 = ShortTunnelBuildRecordBuilder::default()
            .with_tunnel_id(second_tunnel_id)
            .with_next_tunnel_id(recv_tunnel_id)
            .with_next_router_hash(&our_hash)
            .with_role(HopRole::OutboundEndpoint)
            .with_request_time(time_now)
            .with_request_expiration(expiration)
            .with_next_message_id(message_id) // TODO: different for every message?
            .serialize();

        // derive ck/aead/tunnel keys
        let (pub1, aead1, (reply_key1, layer_key1, iv_key1, else_key1, garlic_key1, garlic_tag1)) = {
            let key1 = EphemeralPrivateKey::new(R::rng());
            let pub1 = key1.public_key().to_vec();
            let (ck, aead) = self.derive_keys_remote(hops[0].identity().static_key(), key1);

            (pub1, aead, self.derive_tunnel_keys(ck))
        };

        let (pub2, aead2, (reply_key2, layer_key2, iv_key2, else_key2, garlic_key2, garlic_tag2)) = {
            let key2 = EphemeralPrivateKey::new(R::rng());
            let pub2 = key2.public_key().to_vec();
            let (ck, aead) = self.derive_keys_remote(hops[1].identity().static_key(), key2);

            (pub2, aead, self.derive_tunnel_keys(ck))
        };

        let state1 = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update(hops[0].identity().static_key().to_bytes())
                .finalize();

            Sha256::new().update(&state).update(&pub1).finalize()
        };

        let state2 = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update(hops[1].identity().static_key().to_bytes())
                .finalize();

            Sha256::new().update(&state).update(&pub2).finalize()
        };

        // encrypt records and append tags into them
        let tag1 = ChaChaPoly::new(&aead1).encrypt_with_ad(&state1, &mut record1).unwrap();
        record1.extend_from_slice(&tag1);

        let state1 = Sha256::new().update(&state1).update(&record1).finalize();

        let tag2 = ChaChaPoly::new(&aead2).encrypt_with_ad(&state2, &mut record2).unwrap();
        record2.extend_from_slice(&tag2);

        let state2 = Sha256::new().update(&state2).update(&record2).finalize();

        // decrypt record2 with reply_key1
        let mut record2 = {
            let mut record = hops[1].identity().hash()[..16].to_vec();
            record.extend_from_slice(&pub2);
            record.extend_from_slice(&record2);

            record
        };

        ChaCha::with_nonce(&reply_key1, 1u64).decrypt(&mut record2);

        let short_build_request = ShortTunnelBuildRequestBuilder::default()
            .with_record(hops[0].identity().hash()[..16].to_vec(), pub1, record1)
            .with_full_record(record2)
            .serialize();

        let message = MessageBuilder::short()
            .with_message_type(MessageType::ShortTunnelBuild)
            .with_message_id(message_id)
            .with_expiration(expiration)
            .with_payload(short_build_request)
            .serialize();

        let mut pending_tunnel = PendingTunnel {
            inbound: false,
            hops: VecDeque::new(),
        };

        pending_tunnel.hops.push_front((
            first_tunnel_id,
            TunnelHopNew {
                role: HopRole::Participant,
                index: 0usize,
                reply_key: reply_key1,
                tunnel_id: first_tunnel_id,
                next_tunnel_id: second_tunnel_id,
                next_router_id: hops[1].identity().id(),
                layer_key: layer_key1,
                iv_key: else_key1,
                state: state1,
                garlic_key: vec![],
                garlic_tag: vec![],
            },
        ));
        pending_tunnel.hops.push_front((
            second_tunnel_id,
            TunnelHopNew {
                role: HopRole::OutboundEndpoint,
                index: 1usize,
                reply_key: reply_key2,
                tunnel_id: second_tunnel_id,
                next_tunnel_id: recv_tunnel_id,
                next_router_id: hops[1].identity().id(),
                layer_key: layer_key2,
                iv_key: iv_key2,
                state: state2,
                garlic_key: garlic_key2,
                garlic_tag: garlic_tag2,
            },
        ));

        self.pending_tunnels.insert(recv_tunnel_id, pending_tunnel);

        (recv_tunnel_id, hops[0].identity().id(), message)
    }

    pub fn create_short_tunnel_build_request_inbound<R: Runtime>(
        &mut self,
        hops: Vec<RouterInfo>,
        our_hash: Vec<u8>,
    ) -> (u32, RouterId, Vec<u8>) {
        assert!(hops.len() == 2);

        let first_tunnel_id = R::rng().next_u32();
        let second_tunnel_id = R::rng().next_u32();
        let recv_tunnel_id = R::rng().next_u32();
        let message_id = R::rng().next_u32();
        let time_now = R::time_since_epoch().as_secs() as u32;
        let expiration = (R::time_since_epoch() + Duration::from_secs(180)).as_secs() as u32;

        tracing::info!("tunnels: {first_tunnel_id} -> {second_tunnel_id} -> {recv_tunnel_id}");
        tracing::info!("message id = {message_id}");

        // first record
        let mut record1 = ShortTunnelBuildRecordBuilder::default()
            .with_tunnel_id(first_tunnel_id)
            .with_next_tunnel_id(second_tunnel_id)
            .with_next_router_hash(hops[1].identity().hash().as_ref())
            .with_role(HopRole::InboundGateway)
            .with_request_time(time_now)
            .with_request_expiration(expiration)
            .with_next_message_id(message_id) // TODO: different for every message?
            .serialize();

        // second record
        let mut record2 = ShortTunnelBuildRecordBuilder::default()
            .with_tunnel_id(second_tunnel_id)
            .with_next_tunnel_id(recv_tunnel_id)
            .with_next_router_hash(&our_hash)
            .with_role(HopRole::Participant)
            .with_request_time(time_now)
            .with_request_expiration(expiration)
            .with_next_message_id(message_id) // TODO: different for every message?
            .serialize();

        // derive ck/aead/tunnel keys
        let (pub1, aead1, (reply_key1, layer_key1, iv_key1, else_key1, garlic_key1, garlic_tag1)) = {
            let key1 = EphemeralPrivateKey::new(R::rng());
            let pub1 = key1.public_key().to_vec();
            let (ck, aead) = self.derive_keys_remote(hops[0].identity().static_key(), key1);

            (pub1, aead, self.derive_tunnel_keys(ck))
        };

        let (pub2, aead2, (reply_key2, layer_key2, iv_key2, else_key2, garlic_key2, garlic_tag2)) = {
            let key2 = EphemeralPrivateKey::new(R::rng());
            let pub2 = key2.public_key().to_vec();
            let (ck, aead) = self.derive_keys_remote(hops[1].identity().static_key(), key2);

            (pub2, aead, self.derive_tunnel_keys(ck))
        };

        let state1 = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update(hops[0].identity().static_key().to_bytes())
                .finalize();

            Sha256::new().update(&state).update(&pub1).finalize()
        };

        let state2 = {
            let state = Sha256::new()
                .update(&self.outbound_state)
                .update(hops[1].identity().static_key().to_bytes())
                .finalize();

            Sha256::new().update(&state).update(&pub2).finalize()
        };

        // encrypt records and append tags into them
        let tag1 = ChaChaPoly::new(&aead1).encrypt_with_ad(&state1, &mut record1).unwrap();
        record1.extend_from_slice(&tag1);

        let state1 = Sha256::new().update(&state1).update(&record1).finalize();

        let tag2 = ChaChaPoly::new(&aead2).encrypt_with_ad(&state2, &mut record2).unwrap();
        record2.extend_from_slice(&tag2);

        let state2 = Sha256::new().update(&state2).update(&record2).finalize();

        // decrypt record2 with reply_key1
        let mut record2 = {
            let mut record = hops[1].identity().hash()[..16].to_vec();
            record.extend_from_slice(&pub2);
            record.extend_from_slice(&record2);

            record
        };

        ChaCha::with_nonce(&reply_key1, 1u64).decrypt(&mut record2);

        let short_build_request = ShortTunnelBuildRequestBuilder::default()
            .with_record(hops[0].identity().hash()[..16].to_vec(), pub1, record1)
            .with_full_record(record2)
            .serialize();

        let message = MessageBuilder::short()
            .with_message_type(MessageType::ShortTunnelBuild)
            .with_message_id(message_id)
            .with_expiration(expiration)
            .with_payload(short_build_request)
            .serialize();

        let mut pending_tunnel = PendingTunnel {
            inbound: true,
            hops: VecDeque::new(),
        };

        pending_tunnel.hops.push_front((
            first_tunnel_id,
            TunnelHopNew {
                role: HopRole::InboundGateway,
                index: 0usize,
                reply_key: reply_key1,
                tunnel_id: first_tunnel_id,
                next_tunnel_id: second_tunnel_id,
                next_router_id: hops[1].identity().id(),
                layer_key: layer_key1,
                iv_key: else_key1,
                state: state1,
                garlic_key: vec![],
                garlic_tag: vec![],
            },
        ));
        pending_tunnel.hops.push_front((
            second_tunnel_id,
            TunnelHopNew {
                role: HopRole::Participant,
                index: 1usize,
                reply_key: reply_key2,
                tunnel_id: second_tunnel_id,
                next_tunnel_id: recv_tunnel_id,
                next_router_id: hops[1].identity().id(),
                layer_key: layer_key2,
                iv_key: iv_key2,
                state: state2,
                garlic_key: garlic_key2,
                garlic_tag: garlic_tag2,
            },
        ));

        self.pending_tunnels.insert(recv_tunnel_id, pending_tunnel);
        self.pending_messages.insert(message_id, recv_tunnel_id);

        (recv_tunnel_id, hops[0].identity().id(), message)
    }

    /// TODO: explain
    // TODO: verify source of this message is the same as last message
    pub fn create_short_tunnel_hop<R: Runtime>(
        &mut self,
        truncated: &Vec<u8>,
        mut payload: Vec<u8>,
        message_id: u32,
    ) -> Option<(Vec<u8>, RouterId, Option<u32>)> {
        if let Some(tunnel_id) = self.pending_messages.remove(&message_id) {
            self.handle_zero_hop_inbound_gateway(tunnel_id, &payload);
            todo!();
        }

        // TODO: better abstraction
        let (index, mut record) = payload[1..]
            .chunks_mut(218)
            .enumerate()
            .find(|(i, chunk)| &chunk[..16] == truncated)?;

        let state = Sha256::new().update(&self.inbound_state).update(&record[16..48]).finalize();
        let (chaining_key, aead_key) =
            self.derive_keys(StaticPublicKey::from_bytes(record[16..48].to_vec()).unwrap());

        let new_state = Sha256::new().update(&state).update(&record[48..]).finalize();

        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelReplyKey").update(&[0x01]).finalize();
        let reply_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelReplyKey")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"SMTunnelLayerKey").update(&[0x01]).finalize();
        let layer_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"SMTunnelLayerKey")
            .update(&[0x02])
            .finalize();

        let else_key = ck.clone();

        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"TunnelLayerIVKey").update(&[0x01]).finalize();
        let iv_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"TunnelLayerIVKey")
            .update(&[0x02])
            .finalize();

        // TODO: garlic tag
        // TODO: save garlic key somewhere
        let mut temp_key = Hmac::new(&ck).update(&[]).finalize();
        let ck = Hmac::new(&temp_key).update(&b"RGarlicKeyAndTag").update(&[0x01]).finalize();
        let garlic_key = Hmac::new(&temp_key)
            .update(&ck)
            .update(&b"RGarlicKeyAndTag")
            .update(&[0x02])
            .finalize();

        let mut test = record[48..].to_vec();
        ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

        let (next_router, message_id, (message_type, tunnel_gateway), next_tunnel_id) = {
            let record = ShortTunnelBuildRecord::parse(&test).unwrap(); // TODO: no unwraps

            tracing::trace!(
                target: LOG_TARGET,
                role = ?record.role(),
                tunnel_id = ?record.tunnel_id(),
                next_tunnel_id = ?record.next_tunnel_id(),
                next_message_id = ?record.next_message_id(),
                next_router_hash = ?base64_encode(record.next_router_hash()),
                "SHORT TUNNEL BUILT",
            );

            let hop = TunnelHop {
                role: record.role(),
                tunnel_id: record.tunnel_id(),
                next_tunnel_id: record.next_tunnel_id(),
                next_router_id: RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                layer_key,
                fragments: HashMap::new(),
                iv_key: match record.role() {
                    HopRole::OutboundEndpoint => iv_key,
                    _ => else_key,
                },
            };
            self.tunnels.insert(TunnelId::from(record.tunnel_id()), hop);

            ((
                RouterId::from(base64_encode(&record.next_router_hash()[..16])),
                record.next_message_id(),
                match record.role() {
                    HopRole::OutboundEndpoint => {
                        if RouterId::from(base64_encode(&record.next_router_hash()[..16]))
                            == RouterId::from(base64_encode(&truncated))
                        {
                            (MessageType::OutboundTunnelBuildReply, false)
                        } else {
                            (MessageType::OutboundTunnelBuildReply, true)
                        }
                    }
                    _ => (MessageType::ShortTunnelBuild, false),
                },
                record.next_tunnel_id(),
            ))
        };

        record[48] = 0x00; // no options
        record[49] = 0x00;
        record[201] = 0x00; // accept

        // TODO: use the loop below for this
        let tag = ChaChaPoly::with_nonce(&reply_key, index as u64)
            .encrypt_with_ad(&new_state, &mut record[0..202])
            .unwrap();
        record[202..218].copy_from_slice(&tag);

        // TODO: fix
        // TODO: fix what?
        for (index_new, record) in payload[1..].chunks_mut(218).enumerate() {
            if index_new == index {
                continue;
            }

            ChaCha::with_nonce(&reply_key, index_new as u64).encrypt(&mut record[..218]);
        }

        if tunnel_gateway {
            let msg = MessageBuilder::standard()
                .with_message_type(message_type)
                .with_message_id(message_id)
                .with_expiration((R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs()) // TODO: fix
                .with_payload(payload)
                .serialize();

            // TODO: garlic encrypt?
            let payload = TunnelGateway {
                tunnel_id: TunnelId::from(next_tunnel_id),
                payload: &msg,
            }
            .serialize();

            let message = MessageBuilder::short()
                .with_message_type(MessageType::TunnelGateway)
                .with_message_id(22222222u32) // TODO: fix
                .with_expiration(11111111u32) // TODO: fix
                .with_payload(payload)
                .serialize();

            Some((message, next_router, None))
        } else {
            // i2np message delivery for local inbound gateway
            if message_type == MessageType::OutboundTunnelBuildReply {
                tracing::error!("local delivery, no i2np wrapping applied");

                let msg = MessageBuilder::standard()
                    .with_message_type(message_type)
                    .with_message_id(message_id)
                    .with_expiration(
                        (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs(),
                    ) // TODO: fix
                    .with_payload(payload)
                    .serialize();

                Some((msg, next_router, Some(next_tunnel_id)))
            } else {
                let msg = MessageBuilder::short()
                    .with_message_type(message_type)
                    .with_message_id(message_id)
                    .with_expiration(
                        (R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs(),
                    ) // TODO: fix
                    .with_payload(payload)
                    .serialize();

                Some((msg, next_router, None))
            }
        }
    }

    pub fn handle_tunnel_data(
        &mut self,
        truncated: &Vec<u8>,
        expiration: u64,
        mut payload: Vec<u8>,
    ) -> Option<(Vec<u8>, RouterId)> {
        // TODO: no unwraps
        let tunnel_data = EncryptedTunnelData::parse(&payload).unwrap();
        let Some(hop) = self.tunnels.get_mut(&tunnel_data.tunnel_id()) else {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = ?tunnel_data.tunnel_id(),
                "tunnel doesn't exist",
            );
            return None;
        };

        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = ?hop.tunnel_id,
            next_tunnel_id = ?hop.next_tunnel_id,
            next_router_id = %hop.next_router_id,
            "tunnel data",
        );

        match hop.role {
            HopRole::InboundGateway => todo!("inbound gateway not supported"),
            HopRole::Participant => {
                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(tunnel_data.iv());

                let mut aes = cbc::Aes::new_encryptor(&hop.layer_key, &iv);
                let ciphertext = aes.encrypt(tunnel_data.ciphertext());

                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(iv);

                let mut out = vec![0u8; 4 + 16 + tunnel_data.ciphertext().len()];

                out[..4].copy_from_slice(&hop.next_tunnel_id.to_be_bytes().to_vec());
                out[4..20].copy_from_slice(&iv);
                out[20..].copy_from_slice(&ciphertext);

                // TODO: fix
                let msg = MessageBuilder::short()
                    .with_message_type(MessageType::TunnelData)
                    .with_message_id(13371338u32)
                    .with_expiration(expiration + 5 * 60)
                    .with_payload(out)
                    .serialize();

                return Some((msg, hop.next_router_id.clone()));
            }
            HopRole::OutboundEndpoint => {
                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(tunnel_data.iv());

                let mut aes = cbc::Aes::new_encryptor(&hop.layer_key, &iv);
                let ciphertext = aes.encrypt(tunnel_data.ciphertext());

                let mut aes = ecb::Aes::new_encryptor(&hop.iv_key);
                let iv = aes.encrypt(iv);

                let res =
                    ciphertext[4..].iter().enumerate().find(|(_, byte)| byte == &&0x0).unwrap();

                let checksum =
                    Sha256::new().update(&ciphertext[4 + res.0 + 1..]).update(&iv).finalize();

                if ciphertext[..4] != checksum[..4] {
                    tracing::warn!(
                        target: LOG_TARGET,
                        payload_checksum = ?ciphertext[..4],
                        calculated = ?checksum[..4],
                        "tunnel data checksum mismatch",
                    );
                    panic!("zzz");
                    return None;
                }

                let our_message = ciphertext[4 + res.0 + 1..].to_vec();
                let message = TunnelData::parse(&our_message).unwrap();

                // TODO: handle all messages
                for message in &message.messages {
                    match message.message_kind {
                        MessageKind::Unfragmented {
                            ref delivery_instructions,
                        } => match delivery_instructions {
                            DeliveryInstruction::Local => tracing::error!("todo: local delivery"),
                            DeliveryInstruction::Router { hash } => {
                                tracing::debug!(hash = ?base64_encode(hash), "router delivery");

                                let Message {
                                    message_type,
                                    message_id,
                                    expiration,
                                    payload,
                                } = Message::parse::<I2NP_STANDARD>(&message.message)
                                    .unwrap();

                                let message = MessageBuilder::short()
                                    .with_message_type(message_type)
                                    .with_message_id(message_id)
                                    .with_expiration(expiration)
                                    .with_payload(payload)
                                    .serialize();

                                return Some((message, RouterId::from(base64_encode(&hash[..16]))));
                            }
                            DeliveryInstruction::Tunnel { hash, tunnel_id } => {
                                tracing::trace!(
                                    ?tunnel_id,
                                    msg_len = ?payload.len(),
                                    hash = ?base64_encode(hash),
                                    "tunnel gateway delivery"
                                );

                                let payload = TunnelGateway {
                                    tunnel_id: TunnelId::from(*tunnel_id),
                                    payload: &message.message,
                                }
                                .serialize();

                                let message = MessageBuilder::short()
                                    .with_message_type(MessageType::TunnelGateway)
                                    .with_message_id(13371338u32) // TODO: fix
                                    .with_expiration(expiration)
                                    .with_payload(payload)
                                    .serialize();

                                return Some((message, RouterId::from(base64_encode(&hash[..16]))));
                            }
                        },
                        MessageKind::FirstFragment {
                            message_id,
                            ref delivery_instructions,
                        } => {
                            tracing::error!(
                                target: LOG_TARGET,
                                tunnel_id = ?hop.tunnel_id,
                                ?message_id,
                                ?delivery_instructions,
                                "first fragment",
                            );

                            tracing::error!("first fragment size = {}", message.message.len());

                            hop.fragments.insert(
                                message_id,
                                FragmentedMessage {
                                    first_fragment: message.message.to_vec(),
                                    delivery_instructions: delivery_instructions.to_owned(),
                                    middle_fragments: BTreeMap::new(),
                                    last_fragment: None,
                                },
                            );
                        }
                        MessageKind::MiddleFragment {
                            message_id,
                            sequence_number,
                        } => {
                            tracing::error!(
                                target: LOG_TARGET,
                                tunnel_id = ?hop.tunnel_id,
                                ?message_id,
                                ?sequence_number,
                                "middle fragment",
                            );

                            let Some(fragmented_message) = hop.fragments.get_mut(&message_id)
                            else {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    tunnel_id = ?hop.tunnel_id,
                                    ?message_id,
                                    "fragmented message doesn't exist",
                                );
                                debug_assert!(false);
                                continue;
                            };

                            tracing::error!("second fragment size = {}", message.message.len());

                            fragmented_message
                                .middle_fragments
                                .insert(sequence_number, message.message.to_vec());
                        }
                        MessageKind::LastFragment {
                            message_id,
                            sequence_number,
                        } => {
                            tracing::error!(
                                target: LOG_TARGET,
                                tunnel_id = ?hop.tunnel_id,
                                ?message_id,
                                ?sequence_number,
                                "last fragment",
                            );

                            let Some(fragmented_message) = hop.fragments.remove(&message_id) else {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    tunnel_id = ?hop.tunnel_id,
                                    ?message_id,
                                    "fragmented message doesn't exist",
                                );
                                debug_assert!(false);
                                continue;
                            };

                            tracing::error!("second fragment size = {}", message.message.len());

                            let size = fragmented_message.first_fragment.len()
                                + message.message.len()
                                + fragmented_message
                                    .middle_fragments
                                    .iter()
                                    .fold(0usize, |acc, (_, message)| acc + message.len());

                            // tracing::error!("combined message size = {size}");

                            let mut combined = vec![0u8; size];
                            let mut offset = 0usize;

                            combined[offset..offset + fragmented_message.first_fragment.len()]
                                .copy_from_slice(&fragmented_message.first_fragment);

                            offset += fragmented_message.first_fragment.len();

                            for (_seq_nro, message) in &fragmented_message.middle_fragments {
                                combined[offset..offset + message.len()].copy_from_slice(&message);
                                offset += message.len();
                            }

                            combined[offset..offset + message.message.len()]
                                .copy_from_slice(message.message);

                            // tracing::error!("combined bytes = {combined:?}");

                            let test = combined[combined.len() - 2113..].to_vec();

                            let msg = Message::parse::<I2NP_STANDARD>(&combined)
                                .expect("valid message");

                            // TODO: handle message

                            // let _ = self.create_tunnel_hop(truncated, msg.payload);
                        }
                    }
                }
            }
        }

        None
        // todo!();
    }

    pub fn handle_garlic_message<R: Runtime>(
        &mut self,
        truncated: &Vec<u8>,
        message_id: u32,
        payload: Vec<u8>,
    ) -> Vec<(Vec<u8>, RouterId)> {
        tracing::trace!(
            target: LOG_TARGET,
            ?message_id,
            payload_len = ?payload.len(),
            "handle garlic message",
        );

        let size = u32::from_be_bytes(TryInto::<[u8; 4]>::try_into(&payload[..4]).unwrap());

        let state = Sha256::new().update(&self.inbound_state).update(&payload[4..36]).finalize();
        let (chaining_key, aead_key) =
            self.derive_keys(StaticPublicKey::from_bytes(payload[4..36].to_vec()).unwrap());

        let mut test = payload[36..].to_vec();
        ChaChaPoly::new(&aead_key).decrypt_with_ad(&state, &mut test).unwrap();

        let message = GarlicMessage::parse(&test).unwrap();
        let mut outputs: Vec<(Vec<u8>, RouterId)> = Vec::new();

        for message in message.blocks {
            match message {
                GarlicMessageBlock::DateTime { timestamp } =>
                    tracing::trace!(target: LOG_TARGET, ?timestamp, "ignore datetime"),
                GarlicMessageBlock::Padding { .. } => {}
                GarlicMessageBlock::GarlicClove {
                    message_type,
                    message_id,
                    expiration,
                    delivery_instructions,
                    message_body,
                } => match (message_type, delivery_instructions) {
                    (MessageType::ShortTunnelBuild, DeliveryInstructions::Local) => {
                        let (msg, hop, maybe_tunnel_delivery) = self
                            .create_short_tunnel_hop::<R>(
                                truncated,
                                message_body.to_vec(),
                                message_id,
                            )
                            .unwrap();
                        assert!(maybe_tunnel_delivery.is_none(), "not handled");

                        outputs.push((msg, hop));
                    }
                    _ => todo!("not handled"),
                },
                _ => todo!("not handled"),
            }
        }

        outputs
    }

    pub fn handle_zero_hop_inbound_gateway(&mut self, tunnel_id: u32, payload: &[u8]) {
        let PendingTunnel { inbound, hops } = self.pending_tunnels.remove(&tunnel_id).unwrap();

        if inbound {
            assert!(payload[1..].len() % 218 == 0);
            let num_records = payload[0];

            let mut message_body = payload[1..].to_vec();

            for (_, hop) in &hops {
                tracing::info!("decrypt record at index = {}", hop.index);

                let mut record = message_body[(hop.index * 218)..((1 + hop.index) * 218)].to_vec();

                ChaChaPoly::with_nonce(&hop.reply_key, hop.index as u64)
                    .decrypt_with_ad(&hop.state, &mut record)
                    .unwrap();

                tracing::info!("accepted = {}", record[201]);

                for idx in 0..(num_records as usize) {
                    if idx != hop.index {
                        let mut record = message_body[(idx * 218)..((1 + idx) * 218)].to_vec();

                        ChaCha::with_nonce(&hop.reply_key, idx as u64).decrypt(&mut record);

                        message_body[(idx * 218)..((1 + idx) * 218)].copy_from_slice(&record);
                    }
                }
            }
        } else {
            let Message {
                message_type,
                message_id,
                expiration,
                mut payload,
            } = Message::parse::<I2NP_STANDARD>(payload).unwrap();

            let (
                _,
                TunnelHopNew {
                    garlic_key,
                    garlic_tag,
                    ..
                },
            ) = hops.iter().find(|(_, hop)| hop.role == HopRole::OutboundEndpoint).unwrap();

            tracing::error!("garlic key = {garlic_key:?}");

            let garlic_tag =
                u64::from_le_bytes(TryInto::<[u8; 8]>::try_into(garlic_tag.clone()).unwrap());

            let test = u32::from_be_bytes(TryInto::<[u8; 4]>::try_into(&payload[..4]).unwrap());
            tracing::error!("payload len = {}, garlic len = {test:?}", payload.len());

            let remote_garlic_tag =
                u64::from_be_bytes(TryInto::<[u8; 8]>::try_into(&payload[4..12]).unwrap());

            tracing::error!("our garlic tag = {garlic_tag}, remote's garlic tag = {garlic_tag}");

            let mut test = payload[12..].to_vec();
            ChaChaPoly::new(&garlic_key)
                .decrypt_with_ad(&payload[4..12], &mut test)
                .unwrap();

            let mut message = GarlicMessage::parse(&test).unwrap();

            for mut message in message.blocks {
                match message {
                    GarlicMessageBlock::GarlicClove {
                        message_type,
                        message_id,
                        expiration,
                        delivery_instructions,
                        ref mut message_body,
                    } => {
                        tracing::error!(
                            "message id = {message_id}, num records = {}",
                            message_body[0]
                        );

                        assert!(message_body[1..].len() % 218 == 0);
                        let num_records = message_body[0];

                        let mut message_body = message_body[1..].to_vec();

                        for (_, hop) in &hops {
                            tracing::info!("decrypt record at index = {}", hop.index);

                            let mut record =
                                message_body[(hop.index * 218)..((1 + hop.index) * 218)].to_vec();

                            ChaChaPoly::with_nonce(&hop.reply_key, hop.index as u64)
                                .decrypt_with_ad(&hop.state, &mut record)
                                .unwrap();

                            tracing::info!("accepted = {}", record[201]);

                            for idx in 0..(num_records as usize) {
                                if idx != hop.index {
                                    let mut record =
                                        message_body[(idx * 218)..((1 + idx) * 218)].to_vec();

                                    ChaCha::with_nonce(&hop.reply_key, idx as u64)
                                        .decrypt(&mut record);

                                    message_body[(idx * 218)..((1 + idx) * 218)]
                                        .copy_from_slice(&record);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        todo!();
    }

    pub fn handle_tunnel_gateway<R: Runtime>(
        &mut self,
        truncated: &Vec<u8>,
        message_id: u32,
        expiration: u64,
        payload: Vec<u8>,
    ) -> crate::Result<(Vec<u8>, RouterId)> {
        let TunnelGateway { tunnel_id, payload } =
            TunnelGateway::parse(&payload).ok_or(Error::InvalidData)?;

        tracing::trace!(
            target: LOG_TARGET,
            ?message_id,
            ?tunnel_id,
            message_type = ?MessageType::from_u8(payload[0]),
            payload_len = ?payload.len(),
            "tunnel gateway",
        );

        if self.pending_tunnels.contains_key(tunnel_id.deref()) {
            self.handle_zero_hop_inbound_gateway(tunnel_id.into(), payload);
        }

        let TunnelHop {
            role: HopRole::InboundGateway,
            next_tunnel_id,
            next_router_id,
            layer_key,
            iv_key,
            ..
        } = self.tunnels.get(&TunnelId::from(tunnel_id)).ok_or(Error::Tunnel(
            TunnelError::TunnelDoesntExist(TunnelId::from(tunnel_id)),
        ))?
        else {
            tracing::warn!(
                target: LOG_TARGET,
                ?tunnel_id,
                "tunnel gateway message received to non-gateway",
            );
            debug_assert!(false);
            return Err(Error::Tunnel(TunnelError::InvalidHop));
        };

        // TODO: implement fragment support
        assert!(
            payload.len() < 1028 - 16 - 4 - 1 - 4 - 3,
            "fragment not implemented"
        );

        // construct `TunnelData` message
        //
        // generate random aes iv, fill in next tunnel id, create delivery instructions for local
        // delivery, calculate checksum for the message and fill in random bytes as padding
        let mut out = vec![0u8; 1028];

        // total message size - tunnel id - aes iv - checksum - flag - delivery instructions -
        // payload
        let padding_size = 1028 - 4 - 16 - 4 - 1 - 3 - payload.len();
        let offset = (R::rng().next_u32() % (1028u32 - padding_size as u32)) as usize;

        R::rng().fill_bytes(&mut out[4..20]);

        // TODO: move this elsewhere, it doesn't belong here
        out[..4].copy_from_slice(&next_tunnel_id.to_be_bytes());
        out[24..24 + padding_size]
            .copy_from_slice(&self.padding_bytes[offset..offset + padding_size]);
        out[24 + padding_size] = 0x00; // zero byte
        out[25 + padding_size] = 0x00; // local delivery
        out[26 + padding_size..28 + padding_size]
            .copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out[28 + padding_size..].copy_from_slice(payload);

        let checksum =
            Sha256::new().update(&out[25 + padding_size..]).update(&out[4..20]).finalize();

        out[20..24].copy_from_slice(&checksum[..4]);

        let res = out[24..].iter().enumerate().find(|(_, byte)| byte == &&0x0).unwrap();

        let checksum2 = Sha256::new().update(&out[24 + res.0 + 1..]).update(&out[4..20]).finalize();

        assert_eq!(checksum, checksum2);

        let mut aes = ecb::Aes::new_encryptor(&iv_key);
        let iv = aes.encrypt(&out[4..20]);

        let mut aes = cbc::Aes::new_encryptor(&layer_key, &iv);
        let ciphertext = aes.encrypt(&out[20..]);

        let mut aes = ecb::Aes::new_encryptor(&iv_key);
        let iv = aes.encrypt(iv);

        out[4..20].copy_from_slice(&iv);
        out[20..].copy_from_slice(&ciphertext);

        let message = MessageBuilder::short()
            .with_message_type(MessageType::TunnelData)
            .with_message_id(13351336)
            .with_expiration(expiration)
            .with_payload(out)
            .serialize();

        Ok((message, next_router_id.clone()))
    }

    pub fn handle_outbound_tunnel_build_reply<R: Runtime>(
        &mut self,
        tunnel_id: u32,
        mut payload: Vec<u8>,
    ) -> crate::Result<(Vec<u8>, RouterId)> {
        let TunnelHop {
            role: HopRole::InboundGateway,
            next_tunnel_id,
            next_router_id,
            layer_key,
            iv_key,
            ..
        } = self.tunnels.get(&TunnelId::from(tunnel_id)).ok_or(Error::Tunnel(
            TunnelError::TunnelDoesntExist(TunnelId::from(tunnel_id)),
        ))?
        else {
            tracing::warn!(
                target: LOG_TARGET,
                ?tunnel_id,
                "tunnel gateway message received to non-gateway",
            );
            debug_assert!(false);
            return Err(Error::Tunnel(TunnelError::InvalidHop));
        };

        // TODO: implement fragment support
        assert!(
            payload.len() < 1028 - 16 - 4 - 1 - 4 - 3,
            "fragmentation not implemented"
        );

        // construct `TunnelData` message
        //
        // generate random aes iv, fill in next tunnel id, create delivery instructions for local
        // delivery, calculate checksum for the message and fill in random bytes as padding
        let mut out = vec![0u8; 1028];

        // total message size - tunnel id - aes iv - checksum - flag - delivery instructions -
        // payload
        let padding_size = 1028 - 4 - 16 - 4 - 1 - 3 - payload.len();
        let offset = (R::rng().next_u32() % (1028u32 - padding_size as u32)) as usize;

        R::rng().fill_bytes(&mut out[4..20]);

        // TODO: move this elsewhere, it doesn't belong here
        out[..4].copy_from_slice(&next_tunnel_id.to_be_bytes());
        out[24..24 + padding_size]
            .copy_from_slice(&self.padding_bytes[offset..offset + padding_size]);
        out[24 + padding_size] = 0x00; // zero byte
        out[25 + padding_size] = 0x00; // local delivery
        out[26 + padding_size..28 + padding_size]
            .copy_from_slice(&(payload.len() as u16).to_be_bytes());
        out[28 + padding_size..].copy_from_slice(&payload);

        let checksum =
            Sha256::new().update(&out[25 + padding_size..]).update(&out[4..20]).finalize();

        out[20..24].copy_from_slice(&checksum[..4]);

        let res = out[24..].iter().enumerate().find(|(_, byte)| byte == &&0x0).unwrap();

        let checksum2 = Sha256::new().update(&out[24 + res.0 + 1..]).update(&out[4..20]).finalize();

        assert_eq!(checksum, checksum2);

        let mut aes = ecb::Aes::new_encryptor(&iv_key);
        let iv = aes.encrypt(&out[4..20]);

        let mut aes = cbc::Aes::new_encryptor(&layer_key, &iv);
        let ciphertext = aes.encrypt(&out[20..]);

        let mut aes = ecb::Aes::new_encryptor(&iv_key);
        let iv = aes.encrypt(iv);

        out[4..20].copy_from_slice(&iv);
        out[20..].copy_from_slice(&ciphertext);

        let message = MessageBuilder::short()
            .with_message_type(MessageType::TunnelData)
            .with_message_id(13351336)
            .with_expiration((R::time_since_epoch() + Duration::from_secs(5 * 60)).as_secs()) // TODO: fix
            .with_payload(out)
            .serialize();

        Ok((message, next_router_id.clone()))
    }
}
