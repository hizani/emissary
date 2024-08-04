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

use crate::primitives::TunnelId;

use alloc::string::String;
use core::fmt;

/// Channel error.
#[derive(Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// Channel is full.
    Full,

    /// Channel is closed.
    Closed,

    /// Channel doesn't exist.
    DoesntExist,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "channel full"),
            Self::Closed => write!(f, "channel closed"),
            Self::DoesntExist => write!(f, "channel doesn't exist"),
        }
    }
}

/// Tunnel message rejection reason.
#[derive(Debug, PartialEq, Eq)]
pub enum RejectionReason {
    /// Message/operation not supported.
    NotSupported,

    /// Invalid checksum.
    InvalidChecksum,
}

/// Tunnel error.
#[derive(Debug, PartialEq, Eq)]
pub enum TunnelError {
    /// Tunnel doesn't exist.
    TunnelDoesntExist(TunnelId),

    /// Invalid hop role for an operation.
    InvalidHop,

    /// Too many hops.
    TooManyHops(usize),

    /// Not enough hops.
    NotEnoughHops(usize),

    /// Invalid tunnel message.
    InvalidMessage,

    /// Tunnel rejected.
    TunnelRejected(u8),

    /// Local record not found in the build request.
    RecordNotFound,

    /// Tunnel message rejected.
    ///
    /// This is different from tunnel rejection.
    MessageRejected(RejectionReason),
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TunnelDoesntExist(tunnel_id) => write!(f, "tunnel ({tunnel_id}) does't exist"),
            Self::InvalidHop => write!(f, "invalid hop role for operation"),
            Self::TooManyHops(hops) => write!(f, "too many hops {hops}"),
            Self::InvalidMessage => write!(f, "invalid tunnel message"),
            Self::TunnelRejected(reason) => write!(f, "tunnel rejected: {reason}"),
            Self::NotEnoughHops(hops) => write!(f, "not enough hops {hops}"),
            Self::RecordNotFound => write!(f, "local record not found"),
            Self::MessageRejected(reason) => write!(f, "message rejected, reason: {reason:?}"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Ed25519(ed25519_dalek::ed25519::Error),
    Chacha20Poly1305(chacha20poly1305::Error),
    IoError(String),
    Socket,
    InvalidData,
    InvalidState,
    NonceOverflow,
    NotSupported,
    EssentialTaskClosed,
    RouterDoesntExist,
    DialFailure,
    Tunnel(TunnelError),
    Channel(ChannelError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(error) => write!(f, "ed25519 error: {error:?}"),
            Self::Chacha20Poly1305(error) => write!(f, "chacha20poly1305 error: {error:?}"),
            Self::Socket => write!(f, "socket failure"),
            Self::InvalidData => write!(f, "invalid data"),
            Self::InvalidState => write!(f, "invalid state"),
            Self::NonceOverflow => write!(f, "nonce overflow"),
            Self::IoError(error) => write!(f, "i/o error: {error:?}"),
            Self::NotSupported => write!(f, "protocol or operation not supported"),
            Self::EssentialTaskClosed => write!(f, "essential task closed"),
            Self::RouterDoesntExist => write!(f, "router doesn't exist"),
            Self::DialFailure => write!(f, "dial failure"),
            Self::Tunnel(error) => write!(f, "tunnel error: {error}"),
            Self::Channel(error) => write!(f, "channel error: {error}"),
        }
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(value: ed25519_dalek::ed25519::Error) -> Self {
        Error::Ed25519(value)
    }
}

impl From<chacha20poly1305::Error> for Error {
    fn from(value: chacha20poly1305::Error) -> Self {
        Error::Chacha20Poly1305(value)
    }
}
