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
    crypto::{base64_decode, SigningPrivateKey, StaticPrivateKey},
    primitives::Destination,
    protocol::Protocol,
};

use hashbrown::HashMap;
use nom::{
    branch::alt,
    bytes::complete::{escaped, is_not, tag, take, take_while1},
    character::complete::{alpha1, alphanumeric1, char, multispace0},
    combinator::{map, opt, recognize},
    error::{make_error, ErrorKind},
    multi::{many0, many0_count},
    sequence::{delimited, pair, preceded, separated_pair, tuple},
    Err, IResult, Parser,
};

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::parser";

/// Parsed command.
///
/// Represent a command that had value form but isn't necessarily
/// a command that `yosemite` recognizes.
struct ParsedCommand<'a> {
    /// Command
    ///
    /// Supported values: `HELLO`, `STATUS` and `STREAM`.
    command: &'a str,

    /// Subcommand.
    ///
    /// Supported values: `REPLY` for `HELLO`, `STATUS` for `SESSION`/`STREAM`.
    subcommand: Option<&'a str>,

    /// Parsed key-value pairs.
    key_value_pairs: HashMap<&'a str, &'a str>,
}

/// Session kind.
///
/// NOTE: `Datagram` and `Anonymous` are currently unsupported
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SessionKind {
    /// Streaming.
    Stream,

    /// Repliable datagram.
    Datagram,

    /// Anonymous datagrams.
    Anonymous,
}

impl From<SessionKind> for Protocol {
    fn from(value: SessionKind) -> Self {
        match value {
            SessionKind::Stream => Protocol::Streaming,
            SessionKind::Datagram => Protocol::Datagram,
            SessionKind::Anonymous => Protocol::Anonymous,
        }
    }
}

/// Supported SAM versions.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SamVersion {
    /// v3.1
    V31,

    /// V3.2
    V32,

    /// V3.3
    V33,
}

impl TryFrom<&str> for SamVersion {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "3.1" => Ok(SamVersion::V31),
            "3.2" => Ok(SamVersion::V32),
            "3.3" => Ok(SamVersion::V33),
            _ => Err(()),
        }
    }
}

impl fmt::Display for SamVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V31 => write!(f, "3.1"),
            Self::V32 => write!(f, "3.2"),
            Self::V33 => write!(f, "3.3"),
        }
    }
}

/// Destination kind.
#[derive(Clone)]
pub enum DestinationKind {
    /// Transient session.
    Transient,

    /// Persistent session.
    Persistent {
        /// Destination.
        destination: Destination,

        /// Private key of the destination.
        private_key: Box<StaticPrivateKey>,

        /// Signing key of the destination.
        signing_key: Box<SigningPrivateKey>,
    },
}

impl fmt::Debug for DestinationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient => f.debug_struct("DestinationKind::Transient").finish(),
            Self::Persistent { .. } =>
                f.debug_struct("DestinationKind::Persistent").finish_non_exhaustive(),
        }
    }
}

impl PartialEq for DestinationKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (DestinationKind::Transient, DestinationKind::Transient) => true,
            (
                DestinationKind::Persistent {
                    destination: dst1,
                    private_key: priv1,
                    signing_key: sign1,
                },
                DestinationKind::Persistent {
                    destination: dst2,
                    private_key: priv2,
                    signing_key: sign2,
                },
            ) =>
                dst1 == dst2
                    && (**priv1).as_ref() == (**priv2).as_ref()
                    && (**sign1).as_ref() == (**sign2).as_ref(),
            _ => false,
        }
    }
}

impl Eq for DestinationKind {}

/// SAMv3 commands received from the client.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SamCommand {
    /// `HELLO VERSION` message.
    Hello {
        /// Minimum supported version, if specified.
        min: Option<SamVersion>,

        /// Maximum supported version, if specified.
        max: Option<SamVersion>,
    },

    /// `SESSION CREATE` message.
    CreateSession {
        /// Session ID.
        session_id: String,

        /// Session kind:
        session_kind: SessionKind,

        /// Destination kind.
        destination: DestinationKind,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `STREAM CONNECT` message.
    Connect {
        /// Session ID.
        session_id: String,

        /// Destination.
        destination: Destination,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `STREAM ACCEPT` message.
    Accept {
        /// Session ID.
        session_id: String,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `STREAM FORWARD` message.
    Forward {
        /// Session ID.
        session_id: String,

        /// Port where the TCP listener is listening on.
        port: u16,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// `NAMING LOOKUP` message.
    NamingLookup {
        /// Hostname to lookup.
        name: String,
    },

    /// Generate destination.
    GenerateDestination,

    /// Dummy event
    Dummy,
}

impl Default for SamCommand {
    fn default() -> Self {
        Self::Dummy
    }
}

impl fmt::Display for SamCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello { min, max } => write!(f, "SamCommand::Hello({:?}, {:?})", min, max),
            Self::CreateSession { session_id, .. } =>
                write!(f, "SamCommand::CreateSession({session_id})"),
            Self::Connect { session_id, .. } =>
                write!(f, "SamCommand::StreamConnect({session_id})"),
            Self::Accept { session_id, .. } => write!(f, "SamCommand::StreamAccept({session_id})"),
            Self::Forward { session_id, .. } => write!(f, "SamCommand::Forward({session_id})"),
            Self::NamingLookup { name } => write!(f, "SamCommand::NamingLookup({name})"),
            Self::GenerateDestination => write!(f, "SamCommand::GenerateDestination"),
            Self::Dummy => unreachable!(),
        }
    }
}

impl<'a> TryFrom<ParsedCommand<'a>> for SamCommand {
    type Error = ();

    fn try_from(mut value: ParsedCommand<'a>) -> Result<Self, Self::Error> {
        match (value.command, value.subcommand) {
            ("HELLO", Some("VERSION")) => Ok(Self::Hello {
                min: value
                    .key_value_pairs
                    .get("MIN")
                    .and_then(|value| SamVersion::try_from(*value).ok()),
                max: value
                    .key_value_pairs
                    .get("MAX")
                    .and_then(|value| SamVersion::try_from(*value).ok()),
            }),
            ("SESSION", Some("CREATE")) => {
                let session_id = value
                    .key_value_pairs
                    .remove("ID")
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "session id missing from `SESSION CREATE`",
                        );
                    })?
                    .to_string();

                let session_kind = match value.key_value_pairs.remove("STYLE") {
                    Some("STREAM") => SessionKind::Stream,
                    style @ (Some("RAW") | Some("DATAGRAM")) => {
                        // currently only forwarded datagrams are supported
                        //
                        // TODO: why is port unused?
                        let _ = value.key_value_pairs.get("PORT").ok_or_else(|| {
                            tracing::warn!(
                                target: LOG_TARGET,
                                "only forwarded raw datagrams are supported",
                            );
                        })?;

                        // if no host was specified, default to localhost
                        if value.key_value_pairs.get("HOST").is_none() {
                            value.key_value_pairs.insert("HOST", "127.0.0.1");
                        }

                        match style {
                            Some("RAW") => SessionKind::Anonymous,
                            Some("DATAGRAM") => SessionKind::Datagram,
                            _ => unreachable!(),
                        }
                    }
                    kind => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            ?kind,
                            "unsupported session kind",
                        );

                        return Err(());
                    }
                };

                let destination = match value.key_value_pairs.remove("DESTINATION") {
                    Some("TRANSIENT") => DestinationKind::Transient,
                    Some(destination) => {
                        let decoded = base64_decode(destination).ok_or(())?;
                        let (rest, destination) =
                            Destination::parse_frame(&decoded).map_err(|_| ())?;
                        let (rest, private_key) =
                            take::<_, _, ()>(32usize)(rest).map_err(|_| ())?;
                        let (_, signing_key) = take::<_, _, ()>(32usize)(rest).map_err(|_| ())?;

                        // conversions are expected succeed since the client is interacting with
                        // a local router and would only crash their onw router if they provided
                        // invalid keying material
                        DestinationKind::Persistent {
                            destination,
                            private_key: Box::new(
                                StaticPrivateKey::from_bytes(private_key).expect("to succeed"),
                            ),
                            signing_key: Box::new(
                                SigningPrivateKey::from_bytes(signing_key).expect("to succeed"),
                            ),
                        }
                    }
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "destination type not specified",
                        );

                        return Err(());
                    }
                };

                Ok(SamCommand::CreateSession {
                    session_id,
                    session_kind,
                    destination,
                    options: value
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("STREAM", Some("CONNECT")) => {
                let session_id = value.key_value_pairs.get("ID").ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "session id missing for `STREAM CONNECT`"
                    );
                })?;
                let destination = value.key_value_pairs.get("DESTINATION").ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "destination missing for `STREAM CONNECT`"
                    );
                })?;

                let decoded = base64_decode(destination).ok_or(())?;
                let destination = Destination::parse(&decoded).ok_or(())?;

                Ok(SamCommand::Connect {
                    session_id: session_id.to_string(),
                    destination,
                    options: value
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("STREAM", Some("ACCEPT")) => {
                let session_id = value.key_value_pairs.get("ID").ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "session id missing for `STREAM ACCEPT`"
                    );
                })?;

                Ok(SamCommand::Accept {
                    session_id: session_id.to_string(),
                    options: value
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("STREAM", Some("FORWARD")) => {
                let session_id = value.key_value_pairs.get("ID").ok_or_else(|| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "session id missing for `STREAM FORWARD`"
                    );
                })?;
                let port = value
                    .key_value_pairs
                    .get("PORT")
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "destination missing for `STREAM FORWARD`"
                        );
                    })?
                    .parse::<u16>()
                    .map_err(|_| ())?;

                Ok(SamCommand::Forward {
                    session_id: session_id.to_string(),
                    port,
                    options: value
                        .key_value_pairs
                        .into_iter()
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                        .collect(),
                })
            }
            ("NAMING", Some("LOOKUP")) => Ok(SamCommand::NamingLookup {
                name: value.key_value_pairs.get("NAME").ok_or(())?.to_string(),
            }),
            ("DEST", Some("GENERATE")) => match value.key_value_pairs.get("SIGNATURE_TYPE") {
                Some(signature_type) if *signature_type == "7" =>
                    Ok(SamCommand::GenerateDestination),
                Some(signature_type) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?signature_type,
                        "unsupported signature type",
                    );
                    Err(())
                }
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "signature type not specified"
                    );
                    Err(())
                }
            },
            (command, subcommand) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    %command,
                    ?subcommand,
                    "unrecognized command",
                );

                Err(())
            }
        }
    }
}

impl SamCommand {
    /// Attempt to parse `input` into `Response`.
    //
    // Non-public method returning `IResult` for cleaner error handling.
    fn parse_inner(input: &str) -> IResult<&str, Self> {
        let (rest, (command, _, subcommand, _, key_value_pairs)) = tuple((
            alt((
                tag("HELLO"),
                tag("SESSION"),
                tag("STREAM"),
                tag("NAMING"),
                tag("DEST"),
            )),
            opt(char(' ')),
            opt(alt((
                tag("VERSION"),
                tag("CREATE"),
                tag("CONNECT"),
                tag("ACCEPT"),
                tag("FORWARD"),
                tag("LOOKUP"),
                tag("GENERATE"),
            ))),
            opt(char(' ')),
            opt(parse_key_value_pairs),
        ))(input)?;

        Ok((
            rest,
            SamCommand::try_from(ParsedCommand {
                command,
                subcommand,
                key_value_pairs: key_value_pairs.unwrap_or(HashMap::new()),
            })
            .map_err(|_| Err::Error(make_error(input, ErrorKind::Fail)))?,
        ))
    }

    /// Attempt to parse `input` into `Response`.
    pub fn parse(input: &str) -> Option<Self> {
        Some(Self::parse_inner(input).ok()?.1)
    }
}

/// Anonymous/repliable datagram.
pub struct Datagram {
    /// Session ID.
    pub session_id: Arc<str>,

    /// Destination of the remote peer where the datagram should be sent.
    pub destination: Destination,

    /// Datagram.
    pub datagram: Vec<u8>,
}

impl Datagram {
    /// Attempt to parse `input` into `Datagram`.
    pub fn parse(input: &[u8]) -> Option<Self> {
        // TODO: reimplement using now
        // TODO: add support for options
        //
        // the datagram starts with `3.x ` sequence which is skipped
        //
        // after it follows the nickname of the session, followed by `Destination` of remote peer
        //
        // the "header" ends in `\n`, followed by the actual datagram
        let nickname_end = input[4..].iter().position(|byte| byte == &b' ')?;
        let dgram_start = input[nickname_end + 5..].iter().position(|byte| byte == &b'\n')?;

        let session_id: Arc<str> =
            Arc::from(core::str::from_utf8(&input[4..nickname_end + 4]).ok()?);

        let destination = {
            let destination =
                core::str::from_utf8(&input[nickname_end + 5..dgram_start + nickname_end + 5])
                    .ok()?;
            let decoded = base64_decode(destination)?;

            Destination::parse(&decoded)?
        };
        let datagram = input[nickname_end + dgram_start + 6..].to_vec();

        Some(Self {
            session_id,
            destination,
            datagram,
        })
    }
}

fn parse_key_value_pairs(input: &str) -> IResult<&str, HashMap<&str, &str>> {
    let (input, key_value_pairs) = many0(preceded(multispace0, parse_key_value))(input)?;
    Ok((input, key_value_pairs.into_iter().collect()))
}

fn parse_key_value(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(parse_key, char('='), parse_value)(input)
}

fn parse_key(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_"), tag(".")))),
    ))
    .parse(input)
}

fn parse_value(input: &str) -> IResult<&str, &str> {
    alt((
        parse_quoted_value,
        map(take_while1(|c: char| !c.is_whitespace()), |s: &str| s),
    ))(input)
}

fn parse_quoted_value(input: &str) -> IResult<&str, &str> {
    delimited(
        char('"'),
        escaped(is_not("\\\""), '\\', alt((tag("\""), tag("\\")))),
        char('"'),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::base64_encode,
        runtime::{mock::MockRuntime, Runtime},
    };
    use bytes::{BufMut, BytesMut};

    #[test]
    fn parse_hello() {
        // min and max are the same
        match SamCommand::parse("HELLO VERSION MIN=3.3 MAX=3.3") {
            Some(SamCommand::Hello {
                min: Some(SamVersion::V33),
                max: Some(SamVersion::V33),
            }) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // no version defined
        match SamCommand::parse("HELLO VERSION") {
            Some(SamCommand::Hello {
                min: None,
                max: None,
            }) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // invalid subcommand
        assert!(SamCommand::parse("HELLO REPLY").is_none());
    }

    #[test]
    fn unrecognized_command() {
        assert!(SamCommand::parse("TEST COMMAND KEY=VALUE").is_none());
    }

    #[test]
    fn parse_session_create_stream() {
        // transient
        match SamCommand::parse(
            "SESSION CREATE STYLE=STREAM ID=test DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        ) {
            Some(SamCommand::CreateSession {
                session_id,
                session_kind: SessionKind::Stream,
                destination: DestinationKind::Transient,
                options,
            }) => {
                assert_eq!(session_id.as_str(), "test");
                assert_eq!(
                    options.get("i2cp.leaseSetEncType"),
                    Some(&"4,0".to_string())
                );
            }
            response => panic!("invalid response: {response:?}"),
        }

        // persistent
        let privkey = {
            let signing_key = SigningPrivateKey::random(MockRuntime::rng());
            let encryption_key = StaticPrivateKey::random(MockRuntime::rng());

            let destination = Destination::new::<MockRuntime>(signing_key.public());

            let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
            out.put_slice(&destination.serialize());
            out.put_slice(encryption_key.as_ref());
            out.put_slice(signing_key.as_ref());

            base64_encode(out)
        };

        match SamCommand::parse(&format!(
            "SESSION CREATE STYLE=STREAM ID=test DESTINATION={privkey} i2cp.leaseSetEncType=4,0"
        )) {
            Some(SamCommand::CreateSession {
                session_id,
                session_kind: SessionKind::Stream,
                destination: DestinationKind::Persistent { .. },
                options,
            }) => {
                assert_eq!(session_id.as_str(), "test");
                assert_eq!(
                    options.get("i2cp.leaseSetEncType"),
                    Some(&"4,0".to_string())
                );
            }
            response => panic!("invalid response: {response:?}"),
        }

        // invalid destination
        assert!(SamCommand::parse(
            "SESSION CREATE STYLE=DATAGRAM ID=test DESTINATION=BASE64_DESTINATION i2cp.leaseSetEncType=4,0",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse(
            "SESSION CREATE STYLE=DATAGRAM DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        )
        .is_none());
    }

    #[test]
    fn parse_stream_connect() {
        let destination = {
            let signing_key = SigningPrivateKey::random(MockRuntime::rng());
            base64_encode(Destination::new::<MockRuntime>(signing_key.public()).serialize())
        };

        match SamCommand::parse(&format!(
            "STREAM CONNECT ID=MM9z52ZwnTTPwfeD DESTINATION={destination} SILENT=false"
        )) {
            Some(SamCommand::Connect {
                session_id,
                options,
                ..
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
            }
            response => panic!("invalid response: {response:?}"),
        }

        // invalid subcommand
        assert!(SamCommand::parse(
            "STREAM CREATE ID=MM9z52ZwnTTPwfeD  DESTINATION=host.i2p SILENT=false",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse("STREAM CONNECT DESTINATION=host.i2p SILENT=false",).is_none());

        // non-transient destination
        assert!(SamCommand::parse("STREAM CONNECT ID=MM9z52ZwnTTPwfeD SILENT=false",).is_none());
    }

    #[test]
    fn parse_stream_accept() {
        match SamCommand::parse("STREAM ACCEPT ID=MM9z52ZwnTTPwfeD SILENT=false") {
            Some(SamCommand::Accept {
                session_id,
                options,
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
            }
            response => panic!("invalid response: {response:?}"),
        }

        // session id missing
        assert!(SamCommand::parse("STREAM ACCEPT SILENT=false").is_none());
    }

    #[test]
    fn parse_stream_forward() {
        match SamCommand::parse("STREAM FORWARD ID=MM9z52ZwnTTPwfeD PORT=8888 SILENT=false") {
            Some(SamCommand::Forward {
                session_id,
                port,
                options,
            }) => {
                assert_eq!(session_id.as_str(), "MM9z52ZwnTTPwfeD");
                assert_eq!(port, 8888);
                assert_eq!(options.get("SILENT"), Some(&"false".to_string()));
            }
            response => panic!("invalid response: {response:?}"),
        }

        // session id missing
        assert!(SamCommand::parse("STREAM FORWARD PORT=8888 SILENT=false").is_none());

        // port missing
        assert!(SamCommand::parse("STREAM FORWARD ID=MM9z52ZwnTTPwfeD SILENT=false").is_none());
    }

    #[test]
    fn parse_naming_lookup() {
        match SamCommand::parse("NAMING LOOKUP NAME=host.i2p") {
            Some(SamCommand::NamingLookup { name }) => {
                assert_eq!(name.as_str(), "host.i2p");
            }
            response => panic!("invalid response: {response:?}"),
        }

        // subcommand missing
        assert!(SamCommand::parse("NAMING").is_none());

        // invalid subcommand
        assert!(SamCommand::parse("NAMING GENERATE").is_none());

        // name missing
        assert!(SamCommand::parse("NAMING LOOKUP").is_none());
    }

    #[test]
    fn parse_dest_generate() {
        match SamCommand::parse("DEST GENERATE SIGNATURE_TYPE=7") {
            Some(SamCommand::GenerateDestination) => {}
            response => panic!("invalid response: {response:?}"),
        }

        // invalid signature type
        assert!(SamCommand::parse("DEST GENERATE SIGNATURE_TYPE=1337").is_none());

        // signature type missing
        assert!(SamCommand::parse("DEST GENERATE").is_none());

        // subcommand missing
        assert!(SamCommand::parse("DEST").is_none());

        // invalid subcommand
        assert!(SamCommand::parse("DEST LOOKUP").is_none());
    }

    #[test]
    fn parse_repliable_datagram() {
        {
            let command = "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        PORT=8888 \
                        HOST=127.2.2.2 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Datagram,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.2.2.2".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no host specified, defaults to 127.0.0.1
        {
            let command = "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        PORT=8888 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Datagram,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.0.0.1".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no port specifed, currently not supported
        {
            let command = "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            assert!(SamCommand::parse(command).is_none());
        }

        // session with persistent destination
        {
            let privkey = {
                let signing_key = SigningPrivateKey::random(MockRuntime::rng());
                let encryption_key = StaticPrivateKey::random(MockRuntime::rng());

                let destination = Destination::new::<MockRuntime>(signing_key.public());

                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice(encryption_key.as_ref());
                out.put_slice(signing_key.as_ref());

                base64_encode(out)
            };

            let command = format!(
                "SESSION CREATE \
                        STYLE=DATAGRAM \
                        ID=test \
                        PORT=8888 \
                        DESTINATION={privkey} \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n"
            );

            match SamCommand::parse(&command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Datagram,
                    destination: DestinationKind::Persistent { .. },
                    options,
                }) => {
                    assert_eq!(session_id.as_str(), "test");
                    assert_eq!(options.get("i2cp.leaseSetEncType"), Some(&"4".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // invalid destination
        assert!(SamCommand::parse(
            "SESSION CREATE STYLE=DATAGRAM PORT=8888 ID=test DESTINATION=BASE64_DESTINATION i2cp.leaseSetEncType=4,0",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse(
            "SESSION CREATE STYLE=DATAGRAM PORT=8888 DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        )
        .is_none());
    }

    #[test]
    fn parse_anonymous_datagram() {
        {
            let command = "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        PORT=8888 \
                        HOST=127.2.2.2 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Anonymous,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.2.2.2".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no host specified, defaults to 127.0.0.1
        {
            let command = "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        PORT=8888 \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            match SamCommand::parse(command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Anonymous,
                    options,
                    ..
                }) => {
                    assert_eq!(session_id, "test");
                    assert_eq!(options.get("HOST"), Some(&"127.0.0.1".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // no port specifed, currently not supported
        {
            let command = "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        DESTINATION=TRANSIENT \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n";

            assert!(SamCommand::parse(command).is_none());
        }

        // session with persistent destination
        {
            let privkey = {
                let signing_key = SigningPrivateKey::random(MockRuntime::rng());
                let encryption_key = StaticPrivateKey::random(MockRuntime::rng());

                let destination = Destination::new::<MockRuntime>(signing_key.public());

                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice(encryption_key.as_ref());
                out.put_slice(signing_key.as_ref());

                base64_encode(out)
            };

            let command = format!(
                "SESSION CREATE \
                        STYLE=RAW \
                        ID=test \
                        PORT=8888 \
                        DESTINATION={privkey} \
                        SIGNATURE_TYPE=7 \
                        i2cp.leaseSetEncType=4\n"
            );

            match SamCommand::parse(&command) {
                Some(SamCommand::CreateSession {
                    session_id,
                    session_kind: SessionKind::Anonymous,
                    destination: DestinationKind::Persistent { .. },
                    options,
                }) => {
                    assert_eq!(session_id.as_str(), "test");
                    assert_eq!(options.get("i2cp.leaseSetEncType"), Some(&"4".to_string()));
                }
                response => panic!("invalid response: {response:?}"),
            }
        }

        // invalid destination
        assert!(SamCommand::parse(
            "SESSION CREATE STYLE=RAW PORT=8888 ID=test DESTINATION=BASE64_DESTINATION i2cp.leaseSetEncType=4,0",
        )
        .is_none());

        // session id missing
        assert!(SamCommand::parse(
            "SESSION CREATE STYLE=RAW PORT=8888 DESTINATION=TRANSIENT i2cp.leaseSetEncType=4,0",
        )
        .is_none());
    }

    #[test]
    fn parse_datagram() {
        let destination = {
            let rng = MockRuntime::rng();
            let signing_key = SigningPrivateKey::random(rng);

            Destination::new::<MockRuntime>(signing_key.public())
        };
        let serialized = {
            let mut out = BytesMut::with_capacity(destination.serialized_len());
            out.put_slice(&destination.serialize());

            base64_encode(out)
        };

        let mut datagram = format!("3.0 test {serialized}\n").as_bytes().to_vec();
        datagram.extend_from_slice(b"hello, world");

        match Datagram::parse(&datagram) {
            Some(Datagram {
                session_id,
                datagram,
                ..
            }) => {
                assert_eq!(*session_id, *"test");
                assert_eq!(datagram, b"hello, world");
            }
            _ => panic!("invalid datagram"),
        }

        {
            let datagram = "3.0 12OzbmMqo3bdv3w8 Mja~hsQgYVQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-Gx\
            CBhVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkTI2v4bEIGFUG5bIrm7Zyx5GfFC0D9UclVJ2QoXrx4GRMja~hsQ\
            gYVQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-GxCBhVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkTI2v4bEI\
            GFUG5bIrm7Zyx5GfFC0D9UclVJ2QoXrx4GRMja~hsQgYVQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-GxCB\
            hVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkTI2v4bEIGFUG5bIrm7Zyx5GfFC0D9UclVJ2QoXrx4GRMja~hsQgY\
            VQblsiubtnLHkZ8ULQP1RyVUnZChevHgZEyNr-GxCBhVBuWyK5u2cseRnxQtA~VHJVSdkKF68eBkQL4ggEoB~o\
            SzcMX2fuc~MDG6lmUbi6G9sfRnscl9uh4BQAEAAcAAA==\nhello, world 1"
                .as_bytes()
                .to_vec();

            match Datagram::parse(&datagram) {
                Some(Datagram {
                    session_id,
                    datagram,
                    ..
                }) => {
                    assert_eq!(*session_id, *"12OzbmMqo3bdv3w8");
                    assert_eq!(datagram, b"hello, world 1");
                }
                _ => panic!("invalid datagram"),
            }
        }
    }
}
