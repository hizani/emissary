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
    crypto::{base64_encode, StaticPublicKey},
    primitives::{Date, Mapping, Str},
};

use hashbrown::HashMap;
use nom::{
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};

use alloc::{vec, vec::Vec};
use core::{fmt, str::FromStr};

/// Transport kind.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum TransportKind {
    /// NTCP2.
    Ntcp2,

    /// SSU2.
    Ssu2,
}

impl TryFrom<Str> for TransportKind {
    type Error = ();

    fn try_from(value: Str) -> Result<Self, Self::Error> {
        let value = value.string();

        // TODO: verify that `2` exists
        if value[0] == b'S' && value[1] == b'S' && value[2] == b'U' {
            return Ok(TransportKind::Ssu2);
        }

        if value[0] == b'N'
            && value[1] == b'T'
            && value[2] == b'C'
            && value[3] == b'P'
            && value[4] == b'2'
        {
            return Ok(TransportKind::Ntcp2);
        }

        Err(())
    }
}

impl TransportKind {
    fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Ntcp2 => Str::from_str("NTCP2").expect("to succeed").serialize(),
            Self::Ssu2 => Str::from_str("NTCP2").expect("to succeed").serialize(),
        }
    }
}

/// Router address information.
//
// TODO: cheaply clonable
#[derive(Debug, Clone)]
pub struct RouterAddress {
    /// Router cost.
    cost: u8,

    /// When the router expires (always 0).
    expires: Date,

    /// Transport.
    transport: TransportKind,

    /// Options.
    options: HashMap<Str, Str>,
}

impl fmt::Display for RouterAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RouterAddress (cost {}, transport {:?}, num options {})\n",
            self.cost,
            self.transport,
            self.options.len()
        )?;

        write!(f, "addresses:\n")?;
        for (key, value) in &self.options {
            write!(f, "--> {key}={value}\n")?;
        }

        Ok(())
    }
}

impl RouterAddress {
    /// Create new unpublished [`RouterAddress`].
    pub fn new_unpublished(static_key: Vec<u8>) -> Self {
        let static_key = StaticPublicKey::from_private_x25519(&static_key).unwrap();
        let key = base64_encode(&static_key.to_vec());

        let mut options = HashMap::<Str, Str>::new();
        options.insert(Str::from_str("v").unwrap(), Str::from_str("2").unwrap());
        options.insert(Str::from_str("s").unwrap(), Str::from_str(&key).unwrap());

        Self {
            cost: 10,
            expires: Date::new(0),
            transport: TransportKind::Ntcp2,
            options,
        }
    }

    /// Create new unpublished [`RouterAddress`].
    pub fn new_published(static_key: Vec<u8>, _port: u16, host: alloc::string::String) -> Self {
        let static_key = StaticPublicKey::from_private_x25519(&static_key).unwrap();
        let key = base64_encode(&static_key.to_vec());

        // TODO: zzz
        let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let mut options = HashMap::<Str, Str>::new();
        options.insert(Str::from_str("v").unwrap(), Str::from_str("2").unwrap());
        options.insert(Str::from_str("s").unwrap(), Str::from_str(&key).unwrap());
        options.insert(
            Str::from_str("host").unwrap(),
            Str::from_str(&host).unwrap(),
        );
        options.insert(
            Str::from_str("port").unwrap(),
            Str::from_str("8888").unwrap(),
        );
        options.insert(
            Str::from_str("i").unwrap(),
            Str::from_str(&base64_encode(iv)).unwrap(),
        );

        Self {
            cost: 10,
            expires: Date::new(0),
            transport: TransportKind::Ntcp2,
            options,
        }
    }

    /// Parse [`RouterAddress`] from `input`, returning rest of `input` and parsed address.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], RouterAddress> {
        let (rest, cost) = be_u8(input)?;
        let (rest, expires) = Date::parse_frame(rest)?;
        let (rest, transport) = Str::parse_frame(rest)?;
        let (rest, options) = Mapping::parse_multi_frame(rest)?;

        Ok((
            rest,
            RouterAddress {
                cost,
                expires,
                transport: TransportKind::try_from(transport)
                    .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?,
                options: Mapping::into_hashmap(options),
            },
        ))
    }

    /// Try to convert `bytes` into a [`RouterAddress`].
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Option<RouterAddress> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    // TODO: zzz
    pub fn serialize(&self) -> Vec<u8> {
        let options = self
            .options
            .clone()
            .into_iter()
            .map(|(key, value)| Mapping::new(key, value).serialize())
            .flatten()
            .collect::<Vec<_>>();

        let transport = self.transport.serialize();
        let size = (options.len() as u16).to_be_bytes().to_vec();
        let mut out = vec![0u8; 1 + 8 + transport.len() + options.len() + 2];

        out[0] = self.cost;
        out[1..9].copy_from_slice(&self.expires.serialize());
        out[9..9 + transport.len()].copy_from_slice(&transport);
        out[9 + transport.len()..9 + transport.len() + 2].copy_from_slice(&size);
        out[9 + transport.len() + 2..9 + transport.len() + 2 + options.len()]
            .copy_from_slice(&options);

        out
    }

    /// Get address cost.
    pub fn cost(&self) -> u8 {
        self.cost
    }

    /// Get address transport.
    pub fn transport(&self) -> &TransportKind {
        &self.transport
    }

    /// Get address options.
    pub fn options(&self) -> &HashMap<Str, Str> {
        &self.options
    }
}
