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

//! Active NTCP2 session.
//!
//1 https://geti2p.net/spec/ntcp2#data-phase

use crate::{
    crypto::{chachapoly::ChaChaPoly, siphash::SipHash},
    runtime::Runtime,
    transports::ntcp2::{
        message::Message,
        session::{KeyContext, Role},
    },
};

use futures::AsyncReadExt;

/// Active NTCP2 session.
pub struct Ntcp2Session<R: Runtime> {
    /// Role of the session.
    role: Role,

    /// Runtime.
    runtime: R,

    /// TCP stream.
    stream: R::TcpStream,

    /// Cipher for outbound messages.
    send_cipher: ChaChaPoly,

    /// Cipher for inbound messages.
    recv_cipher: ChaChaPoly,

    /// SipHasher for (deobfuscating) message lengths.
    sip: SipHash,
}

impl<R: Runtime> Ntcp2Session<R> {
    /// Create new active NTCP2 [`Session`].
    pub fn new(role: Role, runtime: R, stream: R::TcpStream, key_context: KeyContext) -> Self {
        let KeyContext {
            send_key,
            recv_key,
            sip,
        } = key_context;

        Self {
            role,
            runtime,
            stream,
            send_cipher: ChaChaPoly::new(&send_key),
            recv_cipher: ChaChaPoly::new(&recv_key),
            sip,
        }
    }

    /// Get role of the session.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Start [`Session`] event loop.
    pub async fn run(mut self) {
        loop {
            let mut reply = alloc::vec![0u8; 2];
            self.stream.read_exact(&mut reply).await.unwrap();
            let test = u16::from_be_bytes(TryInto::<[u8; 2]>::try_into(reply).unwrap());

            let len = self.sip.deobfuscate(test);

            tracing::info!("read {len} bytes from socket");

            let mut test = alloc::vec![0u8; len as usize];
            self.stream.read_exact(&mut test).await.unwrap();

            let data_block = self.recv_cipher.decrypt(test).unwrap();

            match Message::from_bytes(&data_block) {
                Some(message) => {
                    tracing::info!("message received: {message:?}");
                }
                None => {
                    tracing::warn!("invalid message received, ignoring");
                }
            }
        }
    }
}
