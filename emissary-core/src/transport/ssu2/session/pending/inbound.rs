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
    crypto::{
        chachapoly::ChaChaPoly, hmac::Hmac, noise::NoiseContext, EphemeralPrivateKey,
        StaticPrivateKey, StaticPublicKey,
    },
    error::Ssu2Error,
    runtime::Runtime,
    transport::ssu2::{
        message::{
            Block, DataMessageBuilder, HeaderKind, HeaderReader, RetryBuilder,
            SessionCreatedBuilder,
        },
        session::{
            active::Ssu2SessionContext,
            pending::{PacketRetransmitter, PacketRetransmitterEvent, PendingSsu2SessionStatus},
            KeyContext,
        },
        Packet,
    },
};

use bytes::Bytes;
use futures::FutureExt;
use rand_core::RngCore;
use thingbuf::mpsc::{Receiver, Sender};
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::{
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::ssu2::session::inbound";

/// Inbound SSU2 session context.
pub struct InboundSsu2Context {
    /// Socket address of the remote router.
    pub address: SocketAddr,

    /// Chaining key.
    pub chaining_key: Bytes,

    /// Destination connection ID.
    pub dst_id: u64,

    /// Local intro key.
    pub intro_key: [u8; 32],

    /// `TokenRequest` packet.
    pub pkt: Vec<u8>,

    /// Packet number.
    pub pkt_num: u32,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: make `R::UdpSocket` clonable
    pub pkt_tx: Sender<Packet>,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    pub rx: Receiver<Packet>,

    /// Source connection ID.
    pub src_id: u64,

    /// AEAD state.
    pub state: Bytes,

    /// Local static key.
    pub static_key: StaticPrivateKey,
}

/// Pending session state.
enum PendingSessionState {
    /// Awaiting `SessionRequest` message from remote router.
    AwaitingSessionRequest {
        /// Generated token.
        token: u64,
    },

    /// Awaiting `SessionConfirmed` message from remote router.
    AwaitingSessionConfirmed {
        /// Our ephemeral private key.
        ephemeral_key: EphemeralPrivateKey,

        /// Cipher key for decrypting the second part of the header
        k_header_2: [u8; 32],

        /// Key for decrypting the `SessionCreated` message.
        k_session_created: [u8; 32],
    },

    /// State has been poisoned.
    Poisoned,
}

/// Pending inbound SSU2 session.
pub struct InboundSsu2Session<R: Runtime> {
    /// Socket address of the remote router.
    address: SocketAddr,

    /// Destination connection ID.
    dst_id: u64,

    /// Intro key.
    intro_key: [u8; 32],

    /// Noise context.
    noise_ctx: NoiseContext,

    /// Packet retransmitter.
    pkt_retransmitter: PacketRetransmitter<R>,

    /// TX channel for sending packets to [`Ssu2Socket`].
    //
    // TODO: make `R::UdpSocket` clonable
    pkt_tx: Sender<Packet>,

    /// RX channel for receiving datagrams from `Ssu2Socket`.
    rx: Option<Receiver<Packet>>,

    /// Source connection ID.
    src_id: u64,

    /// Pending session state.
    state: PendingSessionState,

    /// Static key.
    static_key: StaticPrivateKey,
}

impl<R: Runtime> InboundSsu2Session<R> {
    /// Create new [`PendingSsu2Session`].
    //
    // TODO: explain what happens here
    pub fn new(context: InboundSsu2Context) -> Result<Self, Ssu2Error> {
        let InboundSsu2Context {
            address,
            chaining_key,
            dst_id,
            intro_key,
            pkt,
            pkt_num,
            pkt_tx,
            rx,
            src_id,
            state,
            static_key,
        } = context;

        tracing::trace!(
            target: LOG_TARGET,
            ?dst_id,
            ?src_id,
            ?pkt_num,
            "handle `TokenRequest`",
        );

        let mut payload = pkt[32..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&intro_key, pkt_num as u64)
            .decrypt_with_ad(&pkt[..32], &mut payload)?;

        Block::parse(&payload).ok_or_else(|| {
            tracing::warn!(
                target: LOG_TARGET,
                ?dst_id,
                ?src_id,
                "failed to parse message blocks",
            );
            debug_assert!(false);

            Ssu2Error::Malformed
        })?;

        let token = R::rng().next_u64();
        let pkt = RetryBuilder::default()
            .with_k_header_1(intro_key)
            .with_src_id(dst_id)
            .with_dst_id(src_id)
            .with_token(token)
            .with_address(address)
            .build::<R>()
            .to_vec();

        // retry messages are not retransmitted
        if let Err(error) = pkt_tx.try_send(Packet { pkt, address }) {
            tracing::warn!(
                target: LOG_TARGET,
                ?dst_id,
                ?src_id,
                ?address,
                ?error,
                "failed to send `Retry`",
            );
        }

        Ok(Self {
            address,
            dst_id,
            intro_key,
            noise_ctx: NoiseContext::new(
                TryInto::<[u8; 32]>::try_into(chaining_key.to_vec()).expect("to succeed"),
                TryInto::<[u8; 32]>::try_into(state.to_vec()).expect("to succeed"),
            ),
            pkt_retransmitter: PacketRetransmitter::inactive(),
            pkt_tx,
            rx: Some(rx),
            src_id,
            state: PendingSessionState::AwaitingSessionRequest { token },
            static_key,
        })
    }

    /// Handle `SessionRequest` message.
    ///
    /// Attempt to parse `pkt` into `SessionRequest` and if it succeeds, verify that the token it
    /// contains is the once that was sent in `Retry`, send `SessionCreated` as a reply and
    /// transition the inbound state to [`PendingSessionState::AwaitingSessionConfirmed`].
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-request>
    /// <https://geti2p.net/spec/ssu2#sessionrequest-type-0>
    fn on_session_request(
        &mut self,
        mut pkt: Vec<u8>,
        _token: u64,
    ) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        let (ephemeral_key, pkt_num, _recv_token) = match HeaderReader::new(self.intro_key, &mut pkt)?
                .parse(self.intro_key)
                .ok_or(Ssu2Error::InvalidVersion)? // TODO: could be other error
            {
                HeaderKind::SessionRequest {
                    ephemeral_key,
                    net_id: _,
                    pkt_num,
                    token,
                    ..
                } => {
                    // TODO: check net id

                    (ephemeral_key, pkt_num, token)
                }
                kind => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?kind,
                        "invalid message, expected `SessionRequest`",
                    );
                    return Err(Ssu2Error::UnexpectedMessage);
                }
            };

        tracing::trace!(
            target: LOG_TARGET,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            ?pkt_num,
            "handle `SessionRequest`",
        );

        // TODO: extract token and verify it's valid

        // MixHash(header), MiXHash(aepk)
        self.noise_ctx.mix_hash(&pkt[..32]).mix_hash(&pkt[32..64]);

        // MixKey(DH())
        let mut cipher_key = self.noise_ctx.mix_key(&self.static_key, &ephemeral_key);

        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessCreateHeader").update([0x01]).finalize_new();

        // decrypt payload
        let mut payload = pkt[64..pkt.len()].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64)
            .decrypt_with_ad(self.noise_ctx.state(), &mut payload)?;
        cipher_key.zeroize();

        // MixHash(ciphertext)
        self.noise_ctx.mix_hash(&pkt[64..pkt.len()]);

        if Block::parse(&payload).is_none() {
            tracing::warn!(
                target: LOG_TARGET,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                "malformed `SessionRequest` payload",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        }

        let sk = EphemeralPrivateKey::random(R::rng());
        let pk = sk.public();

        // MixKey(DH())
        let cipher_key = self.noise_ctx.mix_key(&sk, &ephemeral_key);

        let mut message = SessionCreatedBuilder::default()
            .with_address(self.address)
            .with_dst_id(self.src_id)
            .with_src_id(self.dst_id)
            .with_ephemeral_key(pk.clone())
            .build::<R>();

        // MixHash(header), MixHash(bepk)
        self.noise_ctx.mix_hash(message.header()).mix_hash(&pk);

        message.encrypt_payload(&cipher_key, 0u64, self.noise_ctx.state());
        message.encrypt_header(self.intro_key, k_header_2);

        // MixHash(ciphertext)
        self.noise_ctx.mix_hash(message.payload());

        // reset packet retransmitter to track `SessionConfirmed` and send the message to remote
        let pkt = message.build().to_vec();
        self.pkt_retransmitter = PacketRetransmitter::session_created(pkt.clone());

        if let Err(error) = self.pkt_tx.try_send(Packet {
            pkt,
            address: self.address,
        }) {
            tracing::warn!(
                target: LOG_TARGET,
                dst_id = ?self.dst_id,
                src_id = ?self.src_id,
                address = ?self.address,
                ?error,
                "failed to send `SessionCreated`",
            );
        }

        // create new session
        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_header_2 =
            Hmac::new(&temp_key).update(b"SessionConfirmed").update([0x01]).finalize_new();

        self.state = PendingSessionState::AwaitingSessionConfirmed {
            ephemeral_key: sk,
            k_header_2,
            k_session_created: cipher_key,
        };

        Ok(None)
    }

    /// Handle `SessionConfirmed` message.
    ///
    /// Attempt to parse `pkt` into `SessionConfirmed` and if it succeeds, derive data phase keys
    /// and send an ACK for the message. Return context for an active session and destroy this
    /// future, allowing [`Ssu2Socket`] to create a new future for the active session.
    ///
    /// `SessionConfirmed` must contain a valid router info.
    ///
    /// <https://geti2p.net/spec/ssu2#kdf-for-session-confirmed-part-1-using-session-created-kdf>
    /// <https://geti2p.net/spec/ssu2#sessionconfirmed-type-2>
    /// <https://geti2p.net/spec/ssu2#kdf-for-data-phase>
    fn on_session_confirmed(
        &mut self,
        mut pkt: Vec<u8>,
        ephemeral_key: EphemeralPrivateKey,
        k_header_2: [u8; 32],
        k_session_created: [u8; 32],
    ) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        match HeaderReader::new(self.intro_key, &mut pkt)?
            .parse(k_header_2)
            .ok_or(Ssu2Error::InvalidVersion)? // TODO: could be other error
        {
            HeaderKind::SessionConfirmed { pkt_num } =>
                if pkt_num != 0 {
                    tracing::warn!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?pkt_num,
                        "`SessionConfirmed` contains non-zero packet number",
                    );
                    return Err(Ssu2Error::Malformed);
                },
            kind => {
                tracing::trace!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    ?kind,
                    "invalid message, expected `SessionRequest`",
                );
                return Err(Ssu2Error::UnexpectedMessage);
            }
        }

        tracing::trace!(
            target: LOG_TARGET,
            dst_id = ?self.dst_id,
            src_id = ?self.src_id,
            "handle `SessionConfirmed`",
        );

        // MixHash(header)
        self.noise_ctx.mix_hash(&pkt[..16]);

        let mut static_key = pkt[16..64].to_vec();
        ChaChaPoly::with_nonce(&k_session_created, 1u64)
            .decrypt_with_ad(self.noise_ctx.state(), &mut static_key)?;

        // MixHash(apk)
        self.noise_ctx.mix_hash(&pkt[16..64]);

        // MixKey(DH())
        let mut cipher_key = self.noise_ctx.mix_key(
            &ephemeral_key,
            &StaticPublicKey::from_bytes(&static_key).expect("to succeed"),
        );

        // decrypt payload
        let mut payload = pkt[64..].to_vec();
        ChaChaPoly::with_nonce(&cipher_key, 0u64)
            .decrypt_with_ad(self.noise_ctx.state(), &mut payload)?;
        cipher_key.zeroize();

        let Some(blocks) = Block::parse(&payload) else {
            tracing::warn!(
                target: LOG_TARGET,
                "failed to parse message blocks of `SessionConfirmed`",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };

        let Some(Block::RouterInfo { router_info }) =
            blocks.iter().find(|block| core::matches!(block, Block::RouterInfo { .. }))
        else {
            tracing::warn!(
                target: LOG_TARGET,
                "`SessionConfirmed` doesn't include router info block",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };

        let Some(intro_key) = router_info.ssu2_intro_key() else {
            tracing::warn!(
                target: LOG_TARGET,
                "router info doesn't contain ssu2 intro key",
            );
            debug_assert!(false);
            return Err(Ssu2Error::Malformed);
        };
        let temp_key = Hmac::new(self.noise_ctx.chaining_key()).update([]).finalize();
        let k_ab = Hmac::new(&temp_key).update([0x01]).finalize();
        let k_ba = Hmac::new(&temp_key).update(&k_ab).update([0x02]).finalize();

        let temp_key = Hmac::new(&k_ab).update([]).finalize();
        let k_data_ab =
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize_new();
        let k_header_2_ab = Hmac::new(&temp_key)
            .update(k_data_ab)
            .update(b"HKDFSSU2DataKeys")
            .update([0x02])
            .finalize_new();

        let temp_key = Hmac::new(&k_ba).update([]).finalize();
        let k_data_ba =
            Hmac::new(&temp_key).update(b"HKDFSSU2DataKeys").update([0x01]).finalize_new();
        let k_header_2_ba = Hmac::new(&temp_key)
            .update(k_data_ba)
            .update(b"HKDFSSU2DataKeys")
            .update([0x02])
            .finalize_new();

        let pkt = DataMessageBuilder::default()
            .with_dst_id(self.src_id)
            .with_pkt_num(0u32)
            .with_key_context(
                intro_key,
                &KeyContext {
                    k_data: k_data_ba,
                    k_header_2: k_header_2_ba,
                },
            )
            .with_ack(0u32, 0u8, None)
            .build();

        Ok(Some(PendingSsu2SessionStatus::NewInboundSession {
            context: Ssu2SessionContext {
                address: self.address,
                dst_id: self.src_id,
                intro_key,
                recv_key_ctx: KeyContext::new(k_data_ab, k_header_2_ab),
                send_key_ctx: KeyContext::new(k_data_ba, k_header_2_ba),
                router_id: router_info.identity.id(),
                pkt_rx: self.rx.take().expect("to exist"),
            },
            pkt,
            target: self.address,
        }))
    }

    /// Handle received packet to a pending session.
    ///
    /// `pkt` contains the full header but the first part of the header has been decrypted by the
    /// `Ssu2Socket`, meaning only the second part of the header must be decrypted by us.
    fn on_packet(&mut self, pkt: Vec<u8>) -> Result<Option<PendingSsu2SessionStatus>, Ssu2Error> {
        match mem::replace(&mut self.state, PendingSessionState::Poisoned) {
            PendingSessionState::AwaitingSessionRequest { token } =>
                self.on_session_request(pkt, token),
            PendingSessionState::AwaitingSessionConfirmed {
                ephemeral_key,
                k_header_2,
                k_session_created,
            } => self.on_session_confirmed(pkt, ephemeral_key, k_header_2, k_session_created),
            PendingSessionState::Poisoned => {
                tracing::warn!(
                    target: LOG_TARGET,
                    dst_id = ?self.dst_id,
                    src_id = ?self.src_id,
                    "inbound session state is poisoned",
                );
                debug_assert!(false);
                Ok(Some(PendingSsu2SessionStatus::SessionTermianted {
                    connection_id: self.dst_id,
                    router_id: None,
                }))
            }
        }
    }
}

impl<R: Runtime> Future for InboundSsu2Session<R> {
    type Output = PendingSsu2SessionStatus;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let pkt = match &mut self.rx {
                None => return Poll::Ready(PendingSsu2SessionStatus::SocketClosed),
                Some(rx) => match rx.poll_recv(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) =>
                        return Poll::Ready(PendingSsu2SessionStatus::SocketClosed),
                    Poll::Ready(Some(Packet { pkt, .. })) => pkt,
                },
            };

            match self.on_packet(pkt) {
                Ok(None) => {}
                Ok(Some(status)) => return Poll::Ready(status),
                Err(error) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?error,
                        "failed to handle packet",
                    );
                }
            }
        }

        match futures::ready!(self.pkt_retransmitter.poll_unpin(cx)) {
            PacketRetransmitterEvent::Retransmit { pkt } => {
                if let Err(error) = self.pkt_tx.try_send(Packet {
                    pkt: pkt.clone(),
                    address: self.address,
                }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        dst_id = ?self.dst_id,
                        src_id = ?self.src_id,
                        ?error,
                        "failed to send packet for retransmission",
                    );
                }

                Poll::Pending
            }
            PacketRetransmitterEvent::Timeout => Poll::Ready(PendingSsu2SessionStatus::Timeout {
                connection_id: self.dst_id,
                router_id: None,
            }),
        }
    }
}
