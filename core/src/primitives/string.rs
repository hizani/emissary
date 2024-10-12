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

//! Implementation of I2P string type.
//!
//! https://geti2p.net/spec/common-structures#string

use crate::{primitives::LOG_TARGET, Error};

use bytes::{BufMut, BytesMut};
use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
    number::complete::be_u8,
    Err, IResult,
};

use alloc::{borrow::ToOwned, string::String, sync::Arc, vec, vec::Vec};
use core::{
    fmt,
    hash::{Hash, Hasher},
    ops,
    str::FromStr,
};

/// I2P string.
#[derive(Debug, Clone)]
pub enum Str {
    Static(&'static str),
    Allocated(Arc<str>),
}

impl From<&'static str> for Str {
    fn from(protocol: &'static str) -> Self {
        Str::Static(protocol)
    }
}

impl fmt::Display for Str {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(protocol) => protocol.fmt(f),
            Self::Allocated(protocol) => protocol.fmt(f),
        }
    }
}

impl From<String> for Str {
    fn from(protocol: String) -> Self {
        Str::Allocated(Arc::from(protocol))
    }
}

impl From<Arc<str>> for Str {
    fn from(protocol: Arc<str>) -> Self {
        Self::Allocated(protocol)
    }
}

impl TryFrom<&[u8]> for Str {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let string = core::str::from_utf8(value)
            .map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    ?error,
                    "failed to parse `Str`",
                );

                ()
            })?
            .to_owned();

        Ok(Self::from(string))
    }
}

impl FromStr for Str {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 255 {
            tracing::warn!(
                target: LOG_TARGET,
                len = ?s.len(),
                "string is too large",
            );
            return Err(Error::InvalidData);
        }

        Ok(Str::from(s.to_owned()))
    }
}

impl ops::Deref for Str {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Static(protocol) => protocol,
            Self::Allocated(protocol) => protocol,
        }
    }
}

impl Hash for Str {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self as &str).hash(state)
    }
}

impl PartialEq for Str {
    fn eq(&self, other: &Self) -> bool {
        (self as &str) == (other as &str)
    }
}

impl Eq for Str {}

impl Str {
    /// Serialize [`Str`] into a byte vector.
    pub fn serialize(self) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(self.len() + 1);

        out.put_u8(self.len() as u8);
        out.put_slice(self.as_bytes());

        out.freeze().to_vec()
    }

    /// Parse [`Str`] from `input`, returning rest of `input` and parsed address.
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], Self> {
        let (rest, size) = be_u8(input)?;
        let (rest, string) = take(size)(rest)?;
        let string =
            Str::try_from(string).map_err(|()| Err::Error(make_error(input, ErrorKind::Fail)))?;

        Ok((rest, string))
    }

    /// Try to convert `bytes` into a [`Str`].
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Str> {
        Some(Self::parse_frame(bytes.as_ref()).ok()?.1)
    }

    /// Get serialized length of [`Str`].
    pub fn serialized_len(&self) -> usize {
        self.len() + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::AsBytes;
    use std::collections::VecDeque;

    #[test]
    fn empty_string() {
        assert!(Str::from_bytes(Vec::new()).is_none());
    }

    #[test]
    fn valid_string() {
        let mut string: VecDeque<u8> =
            String::from("hello, world!").as_bytes().to_vec().try_into().unwrap();
        string.push_front(string.len() as u8);
        let string: Vec<u8> = string.into();

        assert_eq!(Str::from_bytes(string), Some(Str::from("hello, world!")),);
    }

    #[test]
    fn valid_string_with_extra_bytes() {
        let mut string: VecDeque<u8> =
            String::from("hello, world!").as_bytes().to_vec().try_into().unwrap();
        string.push_front(string.len() as u8);
        string.push_back(1);
        string.push_back(2);
        string.push_back(3);
        string.push_back(4);
        let string: Vec<u8> = string.into();

        assert_eq!(Str::from_bytes(string), Some(Str::from("hello, world!")));
    }

    #[test]
    fn extra_bytes_returned() {
        let mut string: VecDeque<u8> =
            String::from("hello, world!").as_bytes().to_vec().try_into().unwrap();
        string.push_front(string.len() as u8);
        string.push_back(1);
        string.push_back(2);
        string.push_back(3);
        string.push_back(4);
        let string: Vec<u8> = string.into();

        let (rest, string) = Str::parse_frame(&string).unwrap();

        assert_eq!(string, Str::from("hello, world!"));
        assert_eq!(rest, [1, 2, 3, 4]);
    }

    #[test]
    fn serialize_works() {
        let bytes = Str::from("hello, world!").serialize();

        assert_eq!(Str::from_bytes(bytes), Some(Str::from("hello, world!")));
    }

    #[test]
    fn contains_substring() {
        let mut string: VecDeque<u8> =
            String::from("hello, world!").as_bytes().to_vec().try_into().unwrap();
        string.push_front(string.len() as u8);
        let string: Vec<u8> = string.into();

        assert!(Str::from_bytes(string).unwrap().contains("world"));
    }

    #[test]
    fn doesnt_contain_substring() {
        let mut string: VecDeque<u8> =
            String::from("hello, world!").as_bytes().to_vec().try_into().unwrap();
        string.push_front(string.len() as u8);
        let string: Vec<u8> = string.into();

        assert!(!Str::from_bytes(string).unwrap().contains("goodbye"));
    }
}
