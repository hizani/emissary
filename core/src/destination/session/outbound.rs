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

//! Outbound ECIES-X25519-AEAD-Ratchet session implementation.

use crate::{
    crypto::{
        chachapoly::ChaChaPoly, hmac::Hmac, sha256::Sha256, StaticPrivateKey, StaticPublicKey,
    },
    destination::session::tagset::{TagSet, TagSetEntry},
    i2np::{
        garlic::{NextKeyBuilder, NextKeyKind},
        Message,
    },
    primitives::DestinationId,
    runtime::Runtime,
    Error,
};

use bytes::{BufMut, Bytes, BytesMut};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use rand_core::RngCore;
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::{
    fmt,
    marker::PhantomData,
    mem,
    ops::{Range, RangeFrom},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination::session::outbound";

/// Number of tags to generate for `NewSessionReply`.
const NSR_TAG_COUNT: usize = 16usize;

/// Minimum length for `NewSessionReply` message.
const NSR_MINIMUM_LEN: usize = 60usize;

/// Ephemeral public key offset in `NewSessionReply` message.
const NSR_EPHEMERAL_PUBKEY_OFFSET: Range<usize> = 12..44;

/// Poly1305 MAC offset in `NewSessionReply` message.
const NSR_POLY1305_MAC_OFFSET: Range<usize> = 44..60;

/// Payload offset in `NewSessionReply` message.
const NSR_PAYLOAD_OFFSET: RangeFrom<usize> = 60..;

/// Outbound session state.
pub enum OutboundSessionState {
    /// `NewSession` message has been sent to remote and the session is waiting for a reply.
    OutboundSessionPending {
        /// Destination ID.
        destination_id: DestinationId,

        /// State (`h` from the specification).
        state: Bytes,

        /// Static private key.
        static_private_key: StaticPrivateKey,

        /// Ephemeral private key.
        ephemeral_private_key: StaticPrivateKey,

        /// Chaining key.
        chaining_key: Vec<u8>,
    },

    /// Session has been negotiated.
    Active {
        /// Destination ID.
        destination_id: DestinationId,

        /// [`TagSet`] for outbound messages.
        send_tag_set: TagSet,

        /// [`TagSet`] for inbound messages.
        recv_tag_set: TagSet,
    },

    /// State has been poisoned.
    Poisoned,
}

impl fmt::Debug for OutboundSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutboundSessionPending { destination_id, .. } => f
                .debug_struct("OutboundSessionState::OutboundSessionPending")
                .field("id", &destination_id)
                .finish_non_exhaustive(),
            Self::Active { destination_id, .. } => f
                .debug_struct("OutboundSessionState::Active")
                .field("id", &destination_id)
                .finish_non_exhaustive(),
            Self::Poisoned =>
                f.debug_struct("OutboundSessionState::Poisoned").finish_non_exhaustive(),
        }
    }
}

/// Outbound session.
pub struct OutboundSession<R: Runtime> {
    /// Outbound session state.
    pub state: OutboundSessionState,

    /// Marker for `Runtime`.
    pub _runtime: PhantomData<R>,
}

impl<R: Runtime> OutboundSession<R> {
    /// Generate garlic tags for the incoming `NewSessionReply`
    ///
    /// This function can only be called once, after the outbound session has been initialized and
    /// its state is `OutboundSessionPending`, for other states the call will panic.
    pub fn generate_new_session_reply_tags(&self) -> impl Iterator<Item = TagSetEntry> {
        let OutboundSessionState::OutboundSessionPending { chaining_key, .. } = &self.state else {
            unreachable!();
        };

        let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
        let tag_set_key =
            Hmac::new(&temp_key).update(&b"SessionReplyTags").update(&[0x01]).finalize();

        let mut nsr_tag_set = TagSet::new(&chaining_key, tag_set_key);

        temp_key.zeroize();

        (0..NSR_TAG_COUNT).map(move |_| nsr_tag_set.next_entry().expect("to succeed"))
    }

    /// Handle `NewSessionReply` from remote destination.
    ///
    /// Decrypt `message` using `tag_set_entry`, derive send and receive tag sets
    /// and return the parsed inner payload of `message`.
    ///
    /// Session is considered active after this function has returned successfully.
    ///
    /// https://geti2p.net/spec/ecies#kdf-for-flags-static-key-section-encrypted-contents
    pub fn handle_new_session_reply(
        &mut self,
        tag_set_entry: TagSetEntry,
        message: Vec<u8>,
    ) -> crate::Result<(Vec<u8>, TagSet, TagSet)> {
        match mem::replace(&mut self.state, OutboundSessionState::Poisoned) {
            // Handle `NewSessionReply` message.
            //
            // https://geti2p.net/spec/ecies#kdf-for-flags-static-key-section-encrypted-contents
            OutboundSessionState::OutboundSessionPending {
                state,
                ephemeral_private_key,
                static_private_key,
                chaining_key,
                destination_id,
            } => {
                if message.len() < NSR_MINIMUM_LEN {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %destination_id,
                        payload_len = ?message.len(),
                        "`NewSessionReply` is too short",
                    );
                    debug_assert!(false);

                    return Err(Error::InvalidData);
                }

                // extract and decode elligator2-encoded public key of the remote destination
                let public_key = {
                    // conversion must succeed since the provided range is correct and
                    // the payload has been confirmed to be large enough to hold the public key
                    let public_key =
                        TryInto::<[u8; 32]>::try_into(&message[NSR_EPHEMERAL_PUBKEY_OFFSET])
                            .expect("to succeed");
                    let new_pubkey = Randomized::from_representative(&public_key)
                        .unwrap()
                        .to_montgomery()
                        .to_bytes();

                    StaticPublicKey::from(new_pubkey)
                };

                // poly1305 mac for the key section (empty payload)
                let mut ciphertext = message[NSR_POLY1305_MAC_OFFSET].to_vec();

                // payload section of the `NewSessionReply`
                let mut payload = message[NSR_PAYLOAD_OFFSET].to_vec();

                // calculate new state with garlic tag & remote's ephemeral public key
                let state = {
                    let state = Sha256::new()
                        .update(&state)
                        .update(&tag_set_entry.tag.to_le_bytes())
                        .finalize();

                    Sha256::new().update(&state).update::<&[u8]>(public_key.as_ref()).finalize()
                };

                // calculate keys from shared secrets derived from ee & es
                let (chaining_key, keydata) = {
                    // ephemeral-ephemeral
                    let mut shared = ephemeral_private_key.diffie_hellman(&public_key);
                    let mut temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                    let mut chaining_key =
                        Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();

                    // static-ephemeral
                    shared = static_private_key.diffie_hellman(&public_key);
                    temp_key = Hmac::new(&chaining_key).update(&shared).finalize();
                    chaining_key = Hmac::new(&temp_key).update(&b"").update(&[0x01]).finalize();
                    let keydata = Hmac::new(&temp_key)
                        .update(&chaining_key)
                        .update(&b"")
                        .update(&[0x02])
                        .finalize();

                    shared.zeroize();
                    temp_key.zeroize();

                    (chaining_key, keydata)
                };

                // verify they poly1305 mac for the key section is correct and return updated state
                let state = {
                    let updated_state = Sha256::new().update(&state).update(&ciphertext).finalize();
                    ChaChaPoly::new(&keydata).decrypt_with_ad(&state, &mut ciphertext)?;

                    updated_state
                };

                // split key into send and receive keys
                let (send_key, recv_key) = {
                    let mut temp_key = Hmac::new(&chaining_key).update(&[]).finalize();
                    let send_key = Hmac::new(&temp_key).update(&[0x01]).finalize();
                    let recv_key =
                        Hmac::new(&temp_key).update(&send_key).update(&[0x02]).finalize();

                    temp_key.zeroize();

                    (send_key, recv_key)
                };

                // initialize send and receive tag sets
                let send_tag_set = TagSet::new(&chaining_key, send_key);
                let recv_tag_set = TagSet::new(chaining_key, &recv_key);

                // decode payload of the `NewSessionReply` message
                let mut temp_key = Hmac::new(&recv_key).update(&[]).finalize();
                let mut payload_key =
                    Hmac::new(&temp_key).update(&b"AttachPayloadKDF").update(&[0x01]).finalize();

                ChaChaPoly::new(&payload_key).decrypt_with_ad(&state, &mut payload)?;

                temp_key.zeroize();
                payload_key.zeroize();

                Ok((payload, send_tag_set, recv_tag_set))
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "invalid state for `NewSessionReply`"
                );
                debug_assert!(false);
                return Err(Error::InvalidState);
            }
        }
    }
}
