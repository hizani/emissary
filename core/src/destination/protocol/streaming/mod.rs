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

// use bytes::{BufMut, BytesMut};
// use nom::{
//     bytes::complete::take,
//     error::{make_error, ErrorKind},
//     number::complete::{be_u16, be_u32, be_u8},
//     Err, IResult,
// };
// use rand_core::RngCore;

// use alloc::{collections::VecDeque, vec::Vec};
// use core::{
//     marker::PhantomData,
//     pin::Pin,
//     task::{Context, Poll, Waker},
// };

// /// Logging target for the file.
// const LOG_TARGET: &str = "emissary::protocol::streaming";

// /// Stream state.
// enum StreamState {
//     /// Outbound stream has been initiated.
//     OutboundInitiated {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Sequence number.
//         seq_nro: u32,
//     },

//     /// Stream is open.
//     Open {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Send stream ID.
//         send_stream_id: u32,

//         /// Sequence number.
//         seq_nro: u32,
//     },
// }

// impl StreamState {
//     /// Get receive stream ID.
//     fn recv_stream_id(&self) -> u32 {
//         match self {
//             Self::OutboundInitiated { recv_stream_id, .. } => *recv_stream_id,
//             Self::Open { recv_stream_id, .. } => *recv_stream_id,
//         }
//     }
// }

// /// Streaming protocol instance.
// pub struct Stream<R: Runtime> {
//     /// Stream state.
//     state: StreamState,

//     /// Pending events.
//     pending_events: VecDeque<StreamEvent>,

//     /// Waker.
//     waker: Option<Waker>,

//     /// Marker for `Runtime`.
//     _runtime: PhantomData<R>,
// }

// impl<R: Runtime> Stream<R> {
//     /// Create new outbound [`Stream`].
//     pub fn new_outbound(destination: Dest) -> (Self, BytesMut) {
//         let mut payload = "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent:
// Mozilla/5.0\r\nAccept: text/html\r\n\r\n".as_bytes();         let mut out =
// BytesMut::with_capacity(payload.len() + 22 + destination.serialized_len());

//         let recv_stream_id = R::rng().next_u32();
//         let seq_nro = 0u32;

//         out.put_u32(0u32); // send stream id
//         out.put_u32(recv_stream_id);
//         out.put_u32(seq_nro);
//         out.put_u32(0u32); // ack through
//         out.put_u8(0u8); // nack count

//         // TODO: signature
//         out.put_u8(10u8); // resend delay, in seconds
//         out.put_u16(0x01 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

//         out.put_u16(destination.serialized_len() as u16);
//         out.put_slice(&destination.serialize());
//         out.put_slice(&payload);

//         // out.put_u16(0x01 | 0x03 | 0x20); // flags: `SYN` + `SIGNATURE_INCLUDED` +
// `FROM_INCLUDED`

//         tracing::error!(
//             target: LOG_TARGET,
//             destination = %destination.id(),
//             ?recv_stream_id,
//             "new outbound stream",
//         );

//         (
//             Self {
//                 state: StreamState::OutboundInitiated {
//                     recv_stream_id,
//                     seq_nro,
//                 },
//                 pending_events: VecDeque::new(),
//                 waker: None,
//                 _runtime: Default::default(),
//             },
//             out,
//         )
//     }

//     /// Handle streaming protocol packet.
//     ///
//     /// Returns a serialized [`Packet`] if `payload` warrants sending a reply to remote.
//     pub fn handle_packet(&mut self, payload: &[u8]) -> crate::Result<()> {
//         let Packet {
//             send_stream_id,
//             recv_stream_id,
//             seq_nro,
//             ack_through,
//             flags,
//             payload,
//             nacks,
//             ..
//         } = Packet::parse(payload).ok_or_else(|| {
//             tracing::warn!(
//                 target: LOG_TARGET,
//                 recv_stream_id = ?self.state.recv_stream_id(),
//                 "failed to parse streaming protocol packet",
//             );

//             Error::InvalidData
//         })?;

//         if self.state.recv_stream_id() != send_stream_id {
//             tracing::warn!(
//                 target: LOG_TARGET,
//                 recv_stream_id = ?self.state.recv_stream_id(),
//                 ?send_stream_id,
//                 "stream id mismatch",
//             );

//             return Err(Error::Streaming(StreamingError::StreamIdMismatch(
//                 send_stream_id,
//                 self.state.recv_stream_id(),
//             )));
//         }

//         tracing::info!("ack received = {ack_through}, sequence number = {seq_nro:}");
//         tracing::error!("payload = {:?}", core::str::from_utf8(payload));

//         if (flags & 0x02) == 0x02 {
//             tracing::info!("stream closed");

//             self.pending_events.push_back(StreamEvent::StreamClosed {
//                 recv_stream_id: self.state.recv_stream_id(),
//                 send_stream_id: recv_stream_id,
//             });
//         }

//         let mut out = BytesMut::with_capacity(22);

//         out.put_u32(recv_stream_id); // send stream id
//         out.put_u32(self.state.recv_stream_id());
//         out.put_u32(0);
//         out.put_u32(seq_nro); // ack through
//         out.put_u8(0u8); // nack count

//         out.put_u8(10u8); // resend delay, in seconds
//         out.put_u16(0); // no flags

//         if core::matches!(self.state, StreamState::OutboundInitiated { .. }) {
//             self.pending_events.push_back(StreamEvent::StreamOpened {
//                 recv_stream_id: self.state.recv_stream_id(),
//                 send_stream_id: recv_stream_id,
//             });
//         }

//         self.state = StreamState::Open {
//             recv_stream_id: self.state.recv_stream_id(),
//             send_stream_id: recv_stream_id,
//             seq_nro: 1,
//         };

//         self.pending_events.push_back(StreamEvent::SendPacket { packet: out });
//         self.waker.take().map(|waker| waker.wake_by_ref());

//         Ok(())
//     }
// }

// /// Events emitted by [`Stream`].
// pub enum StreamEvent {
//     /// Stream has been opened.
//     StreamOpened {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Send stream ID.
//         send_stream_id: u32,
//     },

//     /// Stream has been closed.
//     StreamClosed {
//         /// Receive stream ID.
//         recv_stream_id: u32,

//         /// Send stream ID.
//         send_stream_id: u32,
//     },

//     /// Send packet to remote peer.
//     SendPacket {
//         /// Serialized [`Packet`].
//         packet: BytesMut,
//     },
// }

// impl<R: Runtime> futures::Stream for Stream<R> {
//     type Item = StreamEvent;

//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         self.pending_events.pop_front().map_or_else(
//             || {
//                 self.waker = Some(cx.waker().clone());
//                 Poll::Pending
//             },
//             |event| Poll::Ready(Some(event)),
//         )
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{
//         crypto::{SigningPrivateKey, SigningPublicKey},
//         runtime::{mock::MockRuntime, Runtime},
//     };
//     use futures::StreamExt;

//     #[tokio::test]
//     async fn stream_id_mismatch() {
//         let destination =
//             Dest::new(SigningPublicKey::from_private_ed25519(&vec![1u8; 32]).unwrap());
//         let (mut stream, packet) = Stream::<MockRuntime>::new_outbound(destination.clone());
//         let payload = "hello, world".as_bytes();

//         let mut out = BytesMut::with_capacity(payload.len() + 22 + destination.serialized_len());

//         let recv_stream_id = MockRuntime::rng().next_u32();
//         let seq_nro = 0u32;

//         out.put_u32(stream.state.recv_stream_id().overflowing_add(1).0);
//         out.put_u32(recv_stream_id);
//         out.put_u32(seq_nro);
//         out.put_u32(0u32); // ack through
//         out.put_u8(0u8); // nack count

//         out.put_u8(10u8); // resend delay, in seconds
//         out.put_u16(0x01 | 0x20); // flags: `SYN` + `FROM_INCLUDED`

//         out.put_u16(destination.serialized_len() as u16);
//         out.put_slice(&destination.serialize());
//         out.put_slice(&payload);

//         match stream.handle_packet(out.as_ref()).unwrap_err() {
//             Error::Streaming(StreamingError::StreamIdMismatch(send, recv)) => {
//                 assert_eq!(send, stream.state.recv_stream_id().overflowing_add(1).0);
//                 assert_eq!(recv, stream.state.recv_stream_id());
//             }
//             _ => panic!("invalid error"),
//         }
//     }
// }

use crate::{primitives::Destination as Dest, runtime::Runtime, Error};

mod config;
mod packet;

pub use packet::Packet;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::protocol::streaming";

/// I2P virtual stream manager.
pub struct StreamManager<R: Runtime> {
    _runtime: core::marker::PhantomData<R>,
}

impl<R: Runtime> StreamManager<R> {
    /// Create new [`StreamManager`].
    pub fn new() -> Self {
        Self {
            _runtime: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inbound_stream() {
        let message = vec![
            0, 0, 0, 0, 147, 89, 170, 156, 0, 0, 0, 0, 0, 0, 0, 0, 8, 218, 161, 19, 158, 171, 37,
            231, 42, 184, 77, 151, 195, 43, 104, 68, 122, 115, 11, 107, 107, 192, 67, 196, 29, 90,
            87, 216, 247, 208, 122, 47, 238, 9, 4, 169, 1, 201, 76, 212, 49, 132, 31, 194, 115,
            161, 34, 182, 144, 127, 105, 8, 125, 30, 66, 196, 167, 246, 204, 99, 197, 219, 211,
            209, 0, 72, 75, 69, 191, 131, 76, 212, 49, 132, 31, 194, 115, 161, 34, 182, 144, 127,
            105, 8, 125, 30, 66, 196, 167, 246, 204, 99, 197, 219, 211, 209, 0, 72, 75, 69, 191,
            131, 76, 212, 49, 132, 31, 194, 115, 161, 34, 182, 144, 127, 105, 8, 125, 30, 66, 196,
            167, 246, 204, 99, 197, 219, 211, 209, 0, 72, 75, 69, 191, 131, 76, 212, 49, 132, 31,
            194, 115, 161, 34, 182, 144, 127, 105, 8, 125, 30, 66, 196, 167, 246, 204, 99, 197,
            219, 211, 209, 0, 72, 75, 69, 191, 131, 76, 212, 49, 132, 31, 194, 115, 161, 34, 182,
            144, 127, 105, 8, 125, 30, 66, 196, 167, 246, 204, 99, 197, 219, 211, 209, 0, 72, 75,
            69, 191, 131, 76, 212, 49, 132, 31, 194, 115, 161, 34, 182, 144, 127, 105, 8, 125, 30,
            66, 196, 167, 246, 204, 99, 197, 219, 211, 209, 0, 72, 75, 69, 191, 131, 76, 212, 49,
            132, 31, 194, 115, 161, 34, 182, 144, 127, 105, 8, 125, 30, 66, 196, 167, 246, 204, 99,
            197, 219, 211, 209, 0, 72, 75, 69, 191, 131, 76, 212, 49, 132, 31, 194, 115, 161, 34,
            182, 144, 127, 105, 8, 125, 30, 66, 196, 167, 246, 204, 99, 197, 219, 211, 209, 0, 72,
            75, 69, 191, 131, 76, 212, 49, 132, 31, 194, 115, 161, 34, 182, 144, 127, 105, 8, 125,
            30, 66, 196, 167, 246, 204, 99, 197, 219, 211, 209, 0, 72, 75, 69, 191, 131, 76, 212,
            49, 132, 31, 194, 115, 161, 34, 182, 144, 127, 105, 8, 125, 30, 66, 196, 167, 246, 204,
            99, 197, 219, 211, 209, 0, 72, 75, 69, 191, 131, 76, 212, 49, 132, 31, 194, 115, 161,
            34, 182, 144, 127, 105, 8, 125, 30, 66, 196, 167, 246, 204, 99, 197, 219, 211, 209, 0,
            72, 75, 69, 191, 131, 232, 147, 116, 235, 158, 78, 238, 26, 120, 124, 63, 226, 6, 218,
            142, 79, 149, 177, 94, 40, 137, 148, 148, 54, 65, 169, 219, 81, 147, 10, 63, 58, 5, 0,
            4, 0, 7, 0, 0, 7, 20, 140, 52, 89, 170, 100, 193, 248, 229, 100, 120, 99, 226, 237,
            102, 26, 22, 132, 18, 238, 168, 56, 174, 153, 179, 164, 230, 58, 207, 185, 69, 218,
            245, 201, 151, 92, 37, 85, 176, 137, 64, 170, 96, 10, 168, 12, 10, 77, 204, 154, 245,
            4, 194, 116, 12, 164, 139, 107, 220, 63, 202, 125, 194, 162, 5,
        ];

        let Packet {
            send_stream_id,
            recv_stream_id,
            seq_nro,
            ack_through,
            flags,
            payload,
            nacks,
            ..
        } = Packet::parse(&message).unwrap();

        assert!(flags.synchronize());
        assert_eq!(flags.max_packet_size(), Some(19668));
        assert!(flags.from_included().is_some());
        assert!(flags.signature().is_some());
        assert_eq!(nacks.len(), 8);
    }
}
