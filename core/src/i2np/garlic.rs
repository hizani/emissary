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

use crate::i2np::{MessageType, LOG_TARGET};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u8},
    Err, IResult,
};

use alloc::vec::Vec;
use core::fmt;

/// Garlic message type.
#[derive(Debug)]
pub enum GarlicMessageType {
    /// Date time.
    DateTime,

    /// Termination.
    Termination,

    /// Options.
    Options,

    /// Message number.
    MessageNumber,

    /// Next key.
    NextKey,

    /// ACK.
    ACK,

    /// ACK request.
    ACKRequest,

    /// Garlic clove.
    GarlicClove,

    /// Padding.
    Padding,
}

impl GarlicMessageType {
    /// Attempt to convert `byte` into [`GarlicMessageType`].
    fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::DateTime),
            4 => Some(Self::Termination),
            5 => Some(Self::Options),
            6 => Some(Self::MessageNumber),
            7 => Some(Self::NextKey),
            8 => Some(Self::ACK),
            9 => Some(Self::ACKRequest),
            11 => Some(Self::GarlicClove),
            254 => Some(Self::Padding),
            _ => None,
        }
    }
}

/// Garlic clove delivery instructions.
#[derive(Debug)]
pub enum DeliveryInstructions<'a> {
    /// Clove meant for the local node
    Local,

    /// Clove meant for a `Destination`.
    Destination {
        /// Hash of the destination.
        hash: &'a [u8],
    },

    /// Clove meant for a router.
    Router {
        /// Hash of the router.
        hash: &'a [u8],
    },

    /// Clove meant for a tunnel.
    Tunnel {
        /// Hash of the tunnel.
        hash: &'a [u8],

        /// Tunnel ID.
        tunnel_id: u32,
    },
}

impl<'a> DeliveryInstructions<'a> {
    /// Get serialized length of the delivery instructions.
    fn serialized_len(&self) -> usize {
        match self {
            // 1-byte flag
            Self::Local => 1usize,

            // 1-byte flag + 32-byte destination/router hash
            Self::Destination { .. } | Self::Router { .. } => 33usize,

            // 1-byte flag + 32-byte router hash + 4-byte tunnel id
            Self::Tunnel { .. } => 37usize,
        }
    }
}

/// Garlic message block.
pub enum GarlicMessageBlock<'a> {
    /// Date time.
    DateTime {
        /// Timestamp.
        timestamp: u32,
    },

    /// Session termination.
    Termination {},

    /// Options.
    Options {},

    /// Message number.
    MessageNumber {},

    /// Next key.
    NextKey {},

    /// ACK.
    ACK {},

    /// ACK request.
    ACKRequest {},

    /// Garlic clove.
    GarlicClove {
        /// I2NP message type.
        message_type: MessageType,

        /// Message ID.
        message_id: u32,

        /// Message expiration.
        expiration: u32,

        /// Delivery instructions.
        delivery_instructions: DeliveryInstructions<'a>,

        /// Message body.
        message_body: &'a [u8],
    },

    /// Padding
    Padding {
        /// Padding bytes.
        padding: &'a [u8],
    },
}

impl<'a> fmt::Debug for GarlicMessageBlock<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DateTime { timestamp } => f
                .debug_struct("GarlicMessageBlock::DateTime")
                .field("timestamp", &timestamp)
                .finish(),
            Self::GarlicClove {
                message_type,
                message_id,
                expiration,
                delivery_instructions,
                ..
            } => f
                .debug_struct("GarlicMessageBlock::GarlicClove")
                .field("message_type", &message_type)
                .field("message_id", &message_id)
                .field("expiration", &expiration)
                .field("delivery_instructions", &delivery_instructions)
                .finish_non_exhaustive(),
            Self::Padding { .. } =>
                f.debug_struct("DeliveryInstructions::Padding").finish_non_exhaustive(),
            _ => f.debug_struct("Unknown").finish_non_exhaustive(),
        }
    }
}

/// Garlic message.
#[derive(Debug)]
pub struct GarlicMessage<'a> {
    /// Message blocks.
    pub blocks: Vec<GarlicMessageBlock<'a>>,
}

impl<'a> GarlicMessage<'a> {
    /// Try to parse [`GarlicMessage::DateTime`] from `input`.
    fn parse_date_time(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, size) = be_u16(input)?;
        let (rest, timestamp) = be_u32(rest)?;

        debug_assert!(size == 4, "invalid size for datetime block");

        Ok((rest, GarlicMessageBlock::DateTime { timestamp }))
    }

    /// Try to parse [`DeliveryInstructions`] for [`GarlicMessage::GarlicClove`] from `input`.
    fn parse_delivery_instructions(input: &'a [u8]) -> IResult<&'a [u8], DeliveryInstructions<'a>> {
        let (rest, flag) = be_u8(input)?;

        // TODO: handle gracefully
        assert!(flag >> 7 & 1 == 0, "encrypted garlic");
        assert!(flag >> 4 & 1 == 0, "delay");

        match (flag >> 5) & 0x3 {
            0x00 => Ok((rest, DeliveryInstructions::Local)),
            0x01 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, DeliveryInstructions::Destination { hash }))
            }
            0x02 => {
                let (rest, hash) = take(32usize)(rest)?;

                Ok((rest, DeliveryInstructions::Router { hash }))
            }
            0x03 => {
                let (rest, hash) = take(32usize)(rest)?;
                let (rest, tunnel_id) = be_u32(rest)?;

                Ok((rest, DeliveryInstructions::Tunnel { hash, tunnel_id }))
            }
            _ => panic!("invalid garlic type"), // TODO: don't panic
        }
    }

    /// Try to parse [`GarlicMessage::GarlicClove`] from `input`.
    fn parse_garlic_clove(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, size) = be_u16(input)?;
        let (rest, delivery_instructions) = Self::parse_delivery_instructions(rest)?;
        let (rest, message_type) = be_u8(rest)?;
        let (rest, message_id) = be_u32(rest)?;
        let (rest, expiration) = be_u32(rest)?;

        let message_type = MessageType::from_u8(message_type)
            .ok_or_else(|| Err::Error(make_error(input, ErrorKind::Fail)))?;

        // parse body and make sure it has sane length
        let message_body_len =
            (size as usize).saturating_sub(delivery_instructions.serialized_len() + 1 + 2 * 4);
        let (rest, message_body) = take(message_body_len)(rest)?;

        Ok((
            rest,
            GarlicMessageBlock::GarlicClove {
                message_type,
                message_id,
                expiration,
                delivery_instructions,
                message_body,
            },
        ))
    }

    /// Try to parse [`GarlicMessage::Padding`] from `input`.
    fn parse_padding(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, size) = be_u16(input)?;
        let (rest, padding) = take(size)(rest)?;

        Ok((rest, GarlicMessageBlock::Padding { padding }))
    }

    fn parse_frame(input: &'a [u8]) -> IResult<&'a [u8], GarlicMessageBlock<'a>> {
        let (rest, message_type) = be_u8(input)?;

        match GarlicMessageType::from_u8(message_type) {
            Some(GarlicMessageType::DateTime) => Self::parse_date_time(rest),
            Some(GarlicMessageType::GarlicClove) => Self::parse_garlic_clove(rest),
            Some(GarlicMessageType::Padding) => Self::parse_padding(rest),
            message_type => {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?message_type,
                    "invalid garlic message block",
                );
                return Err(Err::Error(make_error(input, ErrorKind::Fail)));
            }
        }
    }

    /// Recursively parse `input` into a vector of [`GarlicMessageBlock`]s
    fn parse_inner(
        input: &'a [u8],
        mut messages: Vec<GarlicMessageBlock<'a>>,
    ) -> Option<Vec<GarlicMessageBlock<'a>>> {
        let (rest, message) = Self::parse_frame(input).ok()?;
        messages.push(message);

        match rest.is_empty() {
            true => Some(messages),
            false => Self::parse_inner(rest, messages),
        }
    }

    /// Attempt to parse `input` into [`GarlicMessage`].
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        Some(Self {
            blocks: Self::parse_inner(input, Vec::new())?,
        })
    }
}
