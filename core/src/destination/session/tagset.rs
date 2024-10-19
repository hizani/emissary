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
    crypto::{hmac::Hmac, StaticPrivateKey, StaticPublicKey},
    destination::session::{LOG_TARGET, SESSION_DH_RATCHET_THRESHOLD},
    error::Error,
    i2np::garlic::{NextKeyBuilder, NextKeyKind},
    runtime::Runtime,
};

use bytes::{Bytes, BytesMut};
use zeroize::Zeroize;

use alloc::vec::Vec;
use core::{fmt, mem};

/// Maximum number of tags that can be generated from a [`TagSet`]:
///
/// "The maximum number of messages before the DH must ratchet is 65535." [1]
///
/// [1]: https://geti2p.net/spec/ecies#new-session-tags-and-comparison-to-signal
const MAX_TAGS: usize = 65535;

/// Pending tag set.
///
/// Local router has sent `NextKey` message to remote and is waiting to receive
/// remote's public key so the session can be ratcheted.
pub struct PendingTagSet {
    /// Key ID.
    key_id: u16,

    /// Private key for the pending tag set.
    private_key: StaticPrivateKey,

    /// Root key of the previous [`TagSet`].
    root_key: Bytes,
}

impl PendingTagSet {
    /// Create new [`PendingTagSet`].
    pub fn new<R: Runtime>(key_id: u16, root_key: Bytes) -> Self {
        Self {
            key_id,
            private_key: StaticPrivateKey::new(R::rng()),
            root_key,
        }
    }

    /// Get key ID of the [`PendingTagSet`].
    pub fn key_id(&self) -> u16 {
        self.key_id
    }

    /// Get [`StaticPublicKey`] of the [`PendingTagSet`].
    pub fn public_key(&self) -> StaticPublicKey {
        self.private_key.public()
    }

    /// Build [`Tagset`] from [`PendingTagSet`] using remote's `public_key`.
    ///
    /// https://geti2p.net/spec/ecies#dh-ratchet-kdf
    pub fn into_tagset(self, public_key: StaticPublicKey) -> TagSet {
        let shared = self.private_key.diffie_hellman(&public_key);

        // derive new key for the new [`TagSet`]
        let tagset_key = {
            let mut temp_key = Hmac::new(&shared).update(&[]).finalize();
            let mut tagset_key =
                Hmac::new(&temp_key).update(&b"XDHRatchetTagSet").update(&[0x01]).finalize();

            temp_key.zeroize();

            tagset_key
        };

        TagSet::new(self.root_key, tagset_key)
    }
}

/// Key state of [`TagSet`].
///
/// https://geti2p.net/spec/ecies#dh-ratchet-message-flow
enum KeyState {
    /// Initial sessions keys have not been exchanged
    Uninitialized,

    /// Awaiting for a requested reverse key to be received from remote destination.
    ///
    /// Once the reverse key is received, DH is performed between the reverse key and
    /// `private_key` and the [`TagSet`] does a DH ratchet.
    AwaitingReverseKey {
        /// Send key ID.
        send_key_id: u16,

        /// Receive key ID.
        recv_key_id: u16,

        /// Local private key.
        private_key: StaticPrivateKey,
    },

    /// New local key has been created and a `NextKey` block with that key has been sent to remote
    /// destination *without* request to send their reverse key back, causing the remote
    /// destination to reuse their previous key.
    ///
    /// Once the `NextKey` confirmation has been received, a DH ratchet is performed.
    AwaitingReverseKeyConfirmation {
        /// Send key ID.
        send_key_id: u16,

        /// Receive key ID.
        recv_key_id: u16,

        /// Local private key.
        private_key: StaticPrivateKey,

        /// Remote public key.
        public_key: StaticPublicKey,
    },

    /// Key state is active and a new `NextKey` request can be sent if the tag count threshold for
    /// the [`TagSet`] has been crossed.
    Active {
        /// Send key ID.
        send_key_id: u16,

        /// Receive key ID.
        recv_key_id: u16,

        /// Local private key.
        private_key: StaticPrivateKey,

        /// Remote public key.
        public_key: StaticPublicKey,
    },

    /// Key state is is poisoned due to invalid state transition.
    Poisoned,
}

impl KeyState {
    /// Is the [`KeyState`] pending?
    ///
    /// If the key state is pending, no `NextKey` requests can be made.
    fn is_pending(&self) -> bool {
        std::matches!(
            self,
            KeyState::AwaitingReverseKey { .. } | KeyState::AwaitingReverseKeyConfirmation { .. }
        )
    }
}

impl fmt::Debug for KeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => f.debug_struct("KeyState::Uninitialized").finish(),
            Self::AwaitingReverseKey {
                send_key_id,
                recv_key_id,
                private_key,
            } => f
                .debug_struct("KeyState::AwaitingReverseKey")
                .field("send_key_id", &send_key_id)
                .field("recv_key_id", &recv_key_id)
                .finish_non_exhaustive(),
            Self::AwaitingReverseKeyConfirmation {
                send_key_id,
                recv_key_id,
                ..
            } => f
                .debug_struct("KeyState::AwaitingReverseKeyConfirmation")
                .field("send_key_id", &send_key_id)
                .field("recv_key_id", &recv_key_id)
                .finish_non_exhaustive(),
            Self::Active {
                send_key_id,
                recv_key_id,
                ..
            } => f
                .debug_struct("KeyState::Active")
                .field("send_key_id", &send_key_id)
                .field("recv_key_id", &recv_key_id)
                .finish_non_exhaustive(),
            Self::Poisoned => f.debug_struct("KeyState::Poisoned").finish(),
        }
    }
}

/// Key context for a [`TagSet`].
struct KeyContext {
    /// Next root key.
    next_root_key: Bytes,

    /// Session key data.
    session_key_data: Bytes,

    /// Session key constant.
    session_tag_constant: Vec<u8>,

    /// Session tag key.
    session_tag_key: Vec<u8>,

    /// Symmetric key.
    symmetric_key: Vec<u8>,
}

impl KeyContext {
    /// Create new [`KeyContext`] for a [`TagSet`].
    pub fn new(root_key: impl AsRef<[u8]>, tag_set_key: impl AsRef<[u8]>) -> Self {
        let mut temp_key = Hmac::new(root_key.as_ref()).update(tag_set_key.as_ref()).finalize();
        let next_root_key =
            Hmac::new(&temp_key).update(&b"KDFDHRatchetStep").update(&[0x01]).finalize();
        let ratchet_key = Hmac::new(&temp_key)
            .update(&next_root_key)
            .update(&b"KDFDHRatchetStep")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&ratchet_key).update(&[]).finalize();
        let session_tag_key =
            Hmac::new(&temp_key).update(&b"TagAndKeyGenKeys").update(&[0x01]).finalize();
        let symmetric_key = Hmac::new(&temp_key)
            .update(&session_tag_key)
            .update(&b"TagAndKeyGenKeys")
            .update(&[0x02])
            .finalize();

        let mut temp_key = Hmac::new(&session_tag_key).update(&[]).finalize();
        let session_key_data =
            Hmac::new(&temp_key).update(&b"STInitialization").update(&[0x01]).finalize();
        let session_tag_constant = Hmac::new(&temp_key)
            .update(&session_key_data)
            .update(&b"STInitialization")
            .update(&[0x02])
            .finalize();

        Self {
            next_root_key: Bytes::from(next_root_key),
            session_key_data: Bytes::from(session_key_data),
            session_tag_constant,
            session_tag_key,
            symmetric_key,
        }
    }
}

/// Session tag entry.
#[derive(Debug, PartialEq, Eq)]
pub struct TagSetEntry {
    /// Index.
    pub index: u16,

    /// Session key.
    pub key: Bytes,

    /// Session tag.
    pub tag: u64,
}

/// Tag set.
///
/// https://geti2p.net/spec/ecies#sample-implementation
pub struct TagSet {
    /// Key context
    key_context: KeyContext,

    /// Key state, see [`KeyState`] for more details.
    key_state: KeyState,

    /// Receive key ID.
    ///
    /// `None` if new session keys haven't been exchanged.
    recv_key_id: Option<u16>,

    /// Send key ID.
    ///
    /// `None` if new session keys haven't been exchanged.
    send_key_id: Option<u16>,

    /// Next tag index.
    tag_index: u16,

    /// ID of the tag set.
    tag_set_id: u16,
}

impl TagSet {
    /// Create new [`TagSet`].
    pub fn new(root_key: impl AsRef<[u8]>, tag_set_key: impl AsRef<[u8]>) -> Self {
        Self {
            key_state: KeyState::Uninitialized,
            key_context: KeyContext::new(root_key, tag_set_key),
            recv_key_id: None,
            send_key_id: None,
            tag_set_id: 0u16,
            tag_index: 0u16,
        }
    }

    /// Get ID of the [`TagSet`].
    pub fn tag_set_id(&self) -> u16 {
        self.tag_set_id
    }

    /// Get next [`TagSetEntry`].
    ///
    /// Returns `None` if all tags have been used.
    pub fn next_entry(&mut self) -> Option<TagSetEntry> {
        let tag_index = {
            let tag_index = self.tag_index;
            self.tag_index = self.tag_index.checked_add(1)?;

            tag_index
        };

        // ratchet next tag
        let garlic_tag = {
            let mut temp_key = Hmac::new(&self.key_context.session_key_data)
                .update(&self.key_context.session_tag_constant)
                .finalize();

            // store session key data for the next session tag ratchet
            self.key_context.session_key_data = Bytes::from(
                Hmac::new(&temp_key).update(&b"SessionTagKeyGen").update(&[0x01]).finalize(),
            );

            let session_tag_key_data = Hmac::new(&temp_key)
                .update(&self.key_context.session_key_data)
                .update(&b"SessionTagKeyGen")
                .update(&[0x02])
                .finalize();

            BytesMut::from(&session_tag_key_data[0..8]).freeze()
        };

        let symmetric_key = {
            let mut temp_key = Hmac::new(&self.key_context.symmetric_key).update(&[]).finalize();

            // store symmetric key for the next key ratchet
            self.key_context.symmetric_key =
                Hmac::new(&temp_key).update(&b"SymmetricRatchet").update(&[0x01]).finalize();

            let symmetric_key = Hmac::new(&temp_key)
                .update(&self.key_context.symmetric_key)
                .update(&b"SymmetricRatchet")
                .update(&[0x02])
                .finalize();

            BytesMut::from(&symmetric_key[..]).freeze()
        };

        Some(TagSetEntry {
            index: tag_index,
            key: symmetric_key,
            tag: u64::from_le_bytes(
                TryInto::<[u8; 8]>::try_into(garlic_tag.as_ref()).expect("to succeed"),
            ),
        })
    }

    /// Create new [`PendingTagSet`] from current [`TagSet`].
    //
    // TODO: remove
    pub fn create_pending_tagset<R: Runtime>(&self) -> PendingTagSet {
        PendingTagSet::new::<R>(
            self.send_key_id.unwrap_or(0),
            self.key_context.next_root_key.clone(),
        )
    }

    /// Attempt to generate new key for the next DH ratchet.
    ///
    /// If the [`TagSet`] still has enough tags, the function returns early and the session can keep
    /// using the [`Tagset`].
    ///
    /// TODO: finish this comment
    ///
    /// https://geti2p.net/spec/ecies#dh-ratchet-message-flow
    pub fn try_generate_next_key<R: Runtime>(&mut self) -> crate::Result<Option<NextKeyKind>> {
        // more tags can be generated from the current dh ratchet
        if self.tag_index as usize <= SESSION_DH_RATCHET_THRESHOLD || self.key_state.is_pending() {
            return Ok(None);
        }

        match mem::replace(&mut self.key_state, KeyState::Poisoned) {
            KeyState::Uninitialized => {
                let private_key = StaticPrivateKey::new(R::rng());
                let public_key = private_key.public();

                self.key_state = KeyState::AwaitingReverseKey {
                    send_key_id: 0u16,
                    recv_key_id: 0u16,
                    private_key,
                };

                Ok(Some(
                    NextKeyBuilder::forward(0u16)
                        .with_public_key(public_key)
                        .with_request_reverse_key(true)
                        .build(),
                ))
            }
            KeyState::Active {
                send_key_id,
                recv_key_id,
                private_key: old_private_key,
                public_key: old_public_key,
            } => {
                // for even-numbered tag sets, send a new forward key to remote destination and do a
                // dh ratchet with the previous key received the from remote destination
                //
                // for odd-numbered tag sets, send a reverse key request to remote destination, wait
                // until a new key is received and once it's received, do a dh ratchet
                //
                // https://geti2p.net/spec/ecies#dh-ratchet-message-flow
                match self.tag_set_id % 2 != 0 {
                    true => {
                        let private_key = StaticPrivateKey::new(R::rng());
                        let public_key = private_key.public();

                        self.key_state = KeyState::AwaitingReverseKeyConfirmation {
                            send_key_id: send_key_id + 1,
                            recv_key_id,
                            private_key,
                            public_key: old_public_key,
                        };

                        Ok(Some(
                            NextKeyBuilder::forward(send_key_id + 1)
                                .with_public_key(public_key)
                                .build(),
                        ))
                    }
                    false => {
                        self.key_state = KeyState::AwaitingReverseKey {
                            send_key_id,
                            recv_key_id: recv_key_id + 1,
                            private_key: old_private_key,
                        };

                        Ok(Some(
                            NextKeyBuilder::forward(recv_key_id + 1)
                                .with_request_reverse_key(true)
                                .build(),
                        ))
                    }
                }
            }
            state => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    "invalid state for tag set when generating next key",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }

    /// Reinitialize [`TagSet`] by performing a DH ratchet
    ///
    /// Do DH key exchange between `private_key` and `public_key` to generate a new tag set key
    /// which is used, together with the previous root key to generate a new state for the
    /// [`TagSet`].
    ///
    /// Caller must ensure that `send_key_id` and `recv_key_id` are valid for this DH ratchet.
    fn reinitialize_tag_set(
        &mut self,
        private_key: StaticPrivateKey,
        public_key: StaticPublicKey,
        send_key_id: u16,
        recv_key_id: u16,
    ) {
        let tag_set_key = {
            let mut shared = private_key.diffie_hellman(&public_key);
            let mut temp_key = Hmac::new(&shared).update(&[]).finalize();
            let mut tagset_key =
                Hmac::new(&temp_key).update(&b"XDHRatchetTagSet").update(&[0x01]).finalize();

            temp_key.zeroize();

            tagset_key
        };

        // perform a dh ratchet and reset `TagSet`'s state
        {
            self.key_context = KeyContext::new(self.key_context.next_root_key.clone(), tag_set_key);

            // tag set id is calculated as `1 + send key id receive key id`
            //
            // https://geti2p.net/spec/ecies#key-and-tag-set-ids
            self.tag_set_id = 1u16 + send_key_id + recv_key_id;
            self.key_state = KeyState::Active {
                send_key_id,
                recv_key_id,
                private_key,
                public_key: public_key.clone(),
            };

            // for the new tag set, tag numbers start again from zero
            // and progress towards `NUM_TAGS_TO_GENERATE`
            self.tag_index = 0u16;
        }
    }

    /// Handle `NextKey` block received from remote peer.
    pub fn handle_next_key<R: Runtime>(
        &mut self,
        kind: &NextKeyKind,
    ) -> crate::Result<Option<NextKeyKind>> {
        match (mem::replace(&mut self.key_state, KeyState::Poisoned), kind) {
            (
                KeyState::Uninitialized,
                NextKeyKind::ForwardKey {
                    key_id: 0u16,
                    public_key: Some(remote_public_key),
                    reverse_key_requested: true,
                },
            ) => {
                let private_key = StaticPrivateKey::new(R::rng());
                let public_key = private_key.public();
                let tag_set_key = {
                    let mut shared = private_key.diffie_hellman(&remote_public_key);
                    let mut temp_key = Hmac::new(&shared).update(&[]).finalize();
                    let mut tagset_key = Hmac::new(&temp_key)
                        .update(&b"XDHRatchetTagSet")
                        .update(&[0x01])
                        .finalize();

                    temp_key.zeroize();

                    tagset_key
                };

                // perform a dh ratchet and reset `TagSet`'s state
                {
                    self.key_context =
                        KeyContext::new(self.key_context.next_root_key.clone(), tag_set_key);

                    // for the first dh ratchet, send and receive key ids are set to 0
                    self.tag_set_id = 1u16;
                    self.key_state = KeyState::Active {
                        send_key_id: 0u16,
                        recv_key_id: 0u16,
                        private_key,
                        public_key: remote_public_key.clone(),
                    };

                    // for the new tag set, tag numbers start again from zero
                    // and progress towards `NUM_TAGS_TO_GENERATE`
                    self.tag_index = 0u16;
                }

                Ok(Some(NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: Some(public_key),
                }))
            }
            // requested reverse key has been received from remote
            //
            // this is the first dh ratchet done after the session has been initialized and the
            // dstinations have done a key exchange in both directions (sending a forward key and
            // receiving a reverse key)
            //
            // after this dh ratchet is performed, the destinations alternate between who creates
            // a new key and who reuses and old key
            (
                KeyState::AwaitingReverseKey {
                    send_key_id,
                    recv_key_id,
                    private_key,
                },
                NextKeyKind::ReverseKey {
                    key_id,
                    public_key: Some(public_key),
                },
            ) => {
                let tag_set_key = {
                    let mut shared = private_key.diffie_hellman(&public_key);
                    let mut temp_key = Hmac::new(&shared).update(&[]).finalize();
                    let mut tagset_key = Hmac::new(&temp_key)
                        .update(&b"XDHRatchetTagSet")
                        .update(&[0x01])
                        .finalize();

                    temp_key.zeroize();

                    tagset_key
                };

                // perform a dh ratchet and reset `TagSet`'s state
                {
                    self.key_context =
                        KeyContext::new(self.key_context.next_root_key.clone(), tag_set_key);

                    // tag set id is calculated as `1 + send key id receive key id`
                    //
                    // https://geti2p.net/spec/ecies#key-and-tag-set-ids
                    self.tag_set_id = 1u16 + send_key_id + recv_key_id;
                    self.key_state = KeyState::Active {
                        send_key_id,
                        recv_key_id,
                        private_key,
                        public_key: public_key.clone(),
                    };

                    // for the new tag set, tag numbers start again from zero
                    // and progress towards `NUM_TAGS_TO_GENERATE`
                    self.tag_index = 0u16;
                }

                Ok(None)
            }
            // `NextKey` confirmation has been received for the request
            //
            // local destination has sent a new key to remote destination without requesting a
            // reverse key, causing remote destination to reuse the old key
            (
                KeyState::AwaitingReverseKeyConfirmation {
                    send_key_id,
                    recv_key_id,
                    private_key,
                    public_key,
                },
                NextKeyKind::ReverseKey {
                    key_id,
                    public_key: None,
                },
            ) => {
                let tag_set_key = {
                    let mut shared = private_key.diffie_hellman(&public_key);
                    let mut temp_key = Hmac::new(&shared).update(&[]).finalize();
                    let mut tagset_key = Hmac::new(&temp_key)
                        .update(&b"XDHRatchetTagSet")
                        .update(&[0x01])
                        .finalize();

                    temp_key.zeroize();

                    tagset_key
                };

                // perform a dh ratchet and reset `TagSet`'s state
                {
                    self.key_context =
                        KeyContext::new(self.key_context.next_root_key.clone(), tag_set_key);

                    // tag set id is calculated as `1 + send key id receive key id`
                    //
                    // https://geti2p.net/spec/ecies#key-and-tag-set-ids
                    self.tag_set_id = 1u16 + send_key_id + recv_key_id;
                    self.key_state = KeyState::Active {
                        send_key_id,
                        recv_key_id,
                        private_key,
                        public_key,
                    };

                    // for the new tag set, tag numbers start again from zero
                    // and progress towards `NUM_TAGS_TO_GENERATE`
                    self.tag_index = 0u16;
                }

                Ok(None)
            }
            // active key state and remote destination has requested a dh ratchet
            //
            // this is the first kind where remote has sent their new public key without requesting
            // a reverse key, asking the local destination to use the previous key for the dh
            // ratchet
            //
            // the `NextKey` is replied only with a confirmation, without a reverse key
            (
                KeyState::Active {
                    send_key_id,
                    recv_key_id,
                    private_key,
                    ..
                },
                NextKeyKind::ForwardKey {
                    key_id,
                    public_key: Some(remote_public_key),
                    reverse_key_requested: false,
                },
            ) => {
                let tag_set_key = {
                    let mut shared = private_key.diffie_hellman(&remote_public_key);
                    let mut temp_key = Hmac::new(&shared).update(&[]).finalize();
                    let mut tagset_key = Hmac::new(&temp_key)
                        .update(&b"XDHRatchetTagSet")
                        .update(&[0x01])
                        .finalize();

                    temp_key.zeroize();

                    tagset_key
                };

                // perform a dh ratchet and reset `TagSet`'s state
                {
                    self.key_context =
                        KeyContext::new(self.key_context.next_root_key.clone(), tag_set_key);

                    // tag set id is calculated as `1 + send key id receive key id`
                    //
                    // https://geti2p.net/spec/ecies#key-and-tag-set-ids
                    self.tag_set_id = 1u16 + key_id + recv_key_id;
                    self.key_state = KeyState::Active {
                        send_key_id: *key_id,
                        recv_key_id,
                        private_key,
                        public_key: remote_public_key.clone(),
                    };

                    // for the new tag set, tag numbers start again from zero
                    // and progress towards `NUM_TAGS_TO_GENERATE`
                    self.tag_index = 0u16;
                }

                Ok(Some(NextKeyBuilder::reverse(*key_id).build()))
            }
            // active key state and remote destination has requested a dh ratchet
            //
            // this is the second kind where the remote destination is reusing their previous key
            // and is asking us to create a new key, send it to them and do a dh ratchet
            //
            // the `NextKey` is replied with the new public key used for the dh ratchet
            (
                KeyState::Active {
                    send_key_id,
                    recv_key_id,
                    public_key: remote_public_key,
                    ..
                },
                NextKeyKind::ForwardKey {
                    key_id,
                    public_key: None,
                    reverse_key_requested: true,
                },
            ) => {
                let private_key = StaticPrivateKey::new(R::rng());
                let public_key = private_key.public();

                let tag_set_key = {
                    let mut shared = private_key.diffie_hellman(&remote_public_key);
                    let mut temp_key = Hmac::new(&shared).update(&[]).finalize();
                    let mut tagset_key = Hmac::new(&temp_key)
                        .update(&b"XDHRatchetTagSet")
                        .update(&[0x01])
                        .finalize();

                    temp_key.zeroize();

                    tagset_key
                };

                // perform a dh ratchet and reset `TagSet`'s state
                {
                    self.key_context =
                        KeyContext::new(self.key_context.next_root_key.clone(), tag_set_key);

                    // tag set id is calculated as `1 + send key id receive key id`
                    //
                    // https://geti2p.net/spec/ecies#key-and-tag-set-ids
                    self.tag_set_id = 1u16 + send_key_id + key_id;
                    self.key_state = KeyState::Active {
                        send_key_id,
                        recv_key_id: *key_id,
                        private_key,
                        public_key: remote_public_key.clone(),
                    };

                    // for the new tag set, tag numbers start again from zero
                    // and progress towards `NUM_TAGS_TO_GENERATE`
                    self.tag_index = 0u16;
                }

                Ok(Some(
                    NextKeyBuilder::reverse(*key_id).with_public_key(public_key).build(),
                ))
            }
            (state, kind) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?state,
                    ?kind,
                    "invalid key state/next key kind combination",
                );
                debug_assert!(false);
                Err(Error::InvalidState)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[test]
    fn maximum_tags_generated() {
        let mut tag_set = TagSet::new([1u8; 32], [2u8; 32]);
        let tags = (0..u16::MAX).map(|_| tag_set.next_entry().unwrap()).collect::<Vec<_>>();

        assert_eq!(tags.len(), MAX_TAGS);
    }

    #[test]
    fn full_dh_ratchet_cycle() {
        let mut send_tag_set = TagSet::new([1u8; 32], [2u8; 32]);
        let mut recv_tag_set = TagSet::new([1u8; 32], [2u8; 32]);

        // generate tags until the first dh ratchet can be done
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 0u16,
                    public_key: Some(_),
                    reverse_key_requested: true,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 0u16,
                    public_key: Some(_),
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send and receive key ids are 0
        // * tag set id 1
        // * tag index is 0
        // * tag sets have each other's public keys stored
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 1);
        assert_eq!(recv_tag_set.tag_set_id, 1);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 0,
                recv_key_id: 0,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 0,
                recv_key_id: 0,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_bytes(), r_pub.to_bytes());
        assert_eq!(r_priv.public().to_bytes(), s_pub.to_bytes());

        // generate tags until the second dh ratchet can be done
        //
        // during this ratchet, owner of the send tag set sends their new key to remote
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 1u16,
                    public_key: Some(_),
                    reverse_key_requested: false,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 1u16,
                    public_key: None,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send key id is 1
        // * receive key ids is 0
        // * tag set id 2
        // * tag index is 0
        // * tag sets have each other's public keys stored
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 2);
        assert_eq!(recv_tag_set.tag_set_id, 2);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 0u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 0u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_bytes(), r_pub.to_bytes());
        assert_eq!(r_priv.public().to_bytes(), s_pub.to_bytes());

        // generate tags until the second dh ratchet can be done
        //
        // during this ratchet, owner of the send tag set requests a reverse key from remote
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 1u16,
                    public_key: None,
                    reverse_key_requested: true,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 1u16,
                    public_key: Some(_),
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send key id is 1
        // * receive key ids is 1
        // * tag set id 3
        // * tag index is 0
        // * tag sets have each other's public keys stored
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 3);
        assert_eq!(recv_tag_set.tag_set_id, 3);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 1u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_bytes(), r_pub.to_bytes());
        assert_eq!(r_priv.public().to_bytes(), s_pub.to_bytes());

        // generate tags until the second dh ratchet can be done
        //
        // during this ratchet, the process cycles back to tag owner sending a key to remote
        loop {
            assert_eq!(send_tag_set.next_entry(), recv_tag_set.next_entry());

            let Some(kind) = send_tag_set.try_generate_next_key::<MockRuntime>().unwrap() else {
                continue;
            };

            match &kind {
                NextKeyKind::ForwardKey {
                    key_id: 2u16,
                    public_key: Some(_),
                    reverse_key_requested: false,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            let kind = recv_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().unwrap();

            match &kind {
                NextKeyKind::ReverseKey {
                    key_id: 2u16,
                    public_key: None,
                } => {}
                kind => panic!("invalid next key kind: {kind:?}"),
            }

            assert!(send_tag_set.handle_next_key::<MockRuntime>(&kind).unwrap().is_none());
            break;
        }

        // verify state is correct after the first dh ratchet
        //
        // * send key id is 1
        // * receive key ids is 1
        // * tag set id 3
        // * tag index is 0
        // * tag sets have each other's public keys stored
        assert_eq!(send_tag_set.tag_index, 0);
        assert_eq!(recv_tag_set.tag_index, 0);
        assert_eq!(send_tag_set.tag_set_id, 4);
        assert_eq!(recv_tag_set.tag_set_id, 4);

        let (s_priv, s_pub) = match &send_tag_set.key_state {
            KeyState::Active {
                send_key_id: 2u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        let (r_priv, r_pub) = match &recv_tag_set.key_state {
            KeyState::Active {
                send_key_id: 2u16,
                recv_key_id: 1u16,
                private_key,
                public_key,
            } => (private_key.clone(), public_key.clone()),
            state => panic!("invalid state: {state:?}"),
        };

        assert_eq!(s_priv.public().to_bytes(), r_pub.to_bytes());
        assert_eq!(r_priv.public().to_bytes(), s_pub.to_bytes());
    }
}
