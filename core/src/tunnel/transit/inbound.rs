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
        aes::{cbc, ecb},
        sha256::Sha256,
    },
    error::{RejectionReason, TunnelError},
    i2np::{
        tunnel::{data::EncryptedTunnelData, gateway::TunnelGateway},
        HopRole, Message, MessageBuilder, MessageType,
    },
    primitives::{RouterId, TunnelId},
    runtime::Runtime,
    tunnel::{
        noise::TunnelKeys, routing_table::RoutingTable, transit::TransitTunnel, TUNNEL_EXPIRATION,
    },
    Error,
};

use bytes::{Buf, BufMut, BytesMut};
use futures::{future::BoxFuture, FutureExt};
use rand_core::RngCore;
use thingbuf::mpsc::Receiver;

use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tunnel::transit::ibgw";

/// Inbound gateway.
pub struct InboundGateway<R: Runtime> {
    /// Tunnel expiration timer.
    expiration_timer: BoxFuture<'static, ()>,

    /// RX channel for receiving messages.
    message_rx: Receiver<Message>,

    /// Metrics handle.
    metrics_handle: R::MetricsHandle,

    /// Next router ID.
    next_router: RouterId,

    /// Next tunnel ID.
    next_tunnel_id: TunnelId,

    /// Random bytes used for tunnel data padding.
    padding_bytes: [u8; 1028],

    /// Routing table.
    routing_table: RoutingTable,

    /// Tunnel ID.
    tunnel_id: TunnelId,

    /// Tunnel key context.
    tunnel_keys: TunnelKeys,
}

impl<R: Runtime> InboundGateway<R> {
    /// Handle `TunnelGateway` message.
    fn handle_tunnel_data(
        &mut self,
        tunnel_data: &EncryptedTunnelData,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        tracing::warn!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            "tunnel data received to inbound gateway",
        );

        Err(Error::Tunnel(TunnelError::MessageRejected(
            RejectionReason::NotSupported,
        )))
    }

    fn handle_tunnel_gateway(
        &mut self,
        tunnel_gateway: &TunnelGateway,
    ) -> crate::Result<(RouterId, Vec<u8>)> {
        tracing::trace!(
            target: LOG_TARGET,
            tunnel_id = %self.tunnel_id,
            gateway_tunnel_id = %tunnel_gateway.tunnel_id,
            message_type = ?MessageType::from_u8(tunnel_gateway.payload[0]),
            "tunnel gateway",
        );

        // TODO: explain calculation
        if tunnel_gateway.payload.len() >= 1028 - 16 - 4 - 1 - 4 - 3 {
            tracing::warn!(
                target: LOG_TARGET,
                tunnel_id = %self.tunnel_id,
                gateway_tunnel_id = %tunnel_gateway.tunnel_id,
                "fragmentation not supported"
            );

            return Err(Error::Tunnel(TunnelError::MessageRejected(
                RejectionReason::NotSupported,
            )));
        }

        // construct `TunnelData` message
        //
        // generate random aes iv, fill in next tunnel id, create delivery instructions for local
        // delivery, calculate checksum for the message and fill in random bytes as padding
        let mut out = BytesMut::with_capacity(1028);

        // total message size - tunnel id - aes iv - checksum - flag - delivery instructions -
        // payload
        let padding_size = 1028 - 4 - 16 - 4 - 1 - 3 - tunnel_gateway.payload.len();
        let offset = (R::rng().next_u32() % (1028u32 - padding_size as u32)) as usize;
        let aes_iv = {
            let mut iv = [0u8; 16];
            R::rng().fill_bytes(&mut iv);

            iv
        };
        let checksum = Sha256::new()
            .update(&[0x00]) // local delivery
            .update((tunnel_gateway.payload.len() as u16).to_be_bytes())
            .update(&tunnel_gateway.payload)
            .update(&aes_iv)
            .finalize();

        out.put_u32(self.next_tunnel_id.into());
        out.put_slice(&aes_iv);
        out.put_slice(&checksum[..4]);
        out.put_slice(&self.padding_bytes[offset..offset + padding_size]);
        out.put_u8(0x00); // zero byte (end of padding)
        out.put_u8(0x00); // local delivery
        out.put_u16(tunnel_gateway.payload.len() as u16);
        out.put_slice(tunnel_gateway.payload);

        let mut aes = ecb::Aes::new_encryptor(&self.tunnel_keys.iv_key());
        let iv = aes.encrypt(&out[4..20]);

        let mut aes = cbc::Aes::new_encryptor(&self.tunnel_keys.layer_key(), &iv);
        let ciphertext = aes.encrypt(&out[20..]);

        let mut aes = ecb::Aes::new_encryptor(&self.tunnel_keys.iv_key());
        let iv = aes.encrypt(iv);

        out[4..20].copy_from_slice(&iv);
        out[20..].copy_from_slice(&ciphertext);

        let message = MessageBuilder::short()
            .with_message_type(MessageType::TunnelData)
            .with_message_id(R::rng().next_u32())
            .with_expiration((R::time_since_epoch() + Duration::from_secs(8)).as_secs())
            .with_payload(&out)
            .build();

        Ok((self.next_router.clone(), message))
    }
}

impl<R: Runtime> TransitTunnel<R> for InboundGateway<R> {
    fn new(
        tunnel_id: TunnelId,
        next_tunnel_id: TunnelId,
        next_router: RouterId,
        tunnel_keys: TunnelKeys,
        routing_table: RoutingTable,
        metrics_handle: R::MetricsHandle,
        message_rx: Receiver<Message>,
    ) -> Self {
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

        InboundGateway {
            expiration_timer: Box::pin(R::delay(TUNNEL_EXPIRATION)),
            message_rx,
            metrics_handle,
            next_router,
            next_tunnel_id,
            padding_bytes,
            routing_table,
            tunnel_id,
            tunnel_keys,
        }
    }

    fn role(&self) -> HopRole {
        HopRole::InboundGateway
    }
}

impl<R: Runtime> Future for InboundGateway<R> {
    type Output = TunnelId;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(event) = self.message_rx.poll_recv(cx) {
            match event {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        "message channel closed",
                    );
                    return Poll::Ready(self.tunnel_id);
                }
                Some(message) => match message.message_type {
                    MessageType::TunnelGateway => match TunnelGateway::parse(&message.payload) {
                        Some(message) => match self.handle_tunnel_gateway(&message) {
                            Ok((router, message)) => {
                                if let Err(error) = self.routing_table.send_message(router, message)
                                {
                                    tracing::error!(
                                        target: LOG_TARGET,
                                        tunnel_id = %self.tunnel_id,
                                        ?error,
                                        "failed to send message",
                                    )
                                }
                            }
                            Err(error) => tracing::warn!(
                                target: LOG_TARGET,
                                tunnel_id = %self.tunnel_id,
                                ?error,
                                "failed to handle tunnel gateway",
                            ),
                        },
                        None => todo!(),
                    },
                    message_type => tracing::warn!(
                        target: LOG_TARGET,
                        tunnel_id = %self.tunnel_id,
                        ?message_type,
                        "unsupported message",
                    ),
                },
            }
        }

        if let Poll::Ready(_) = self.expiration_timer.poll_unpin(cx) {
            return Poll::Ready(self.tunnel_id);
        }

        Poll::Pending
    }
}
