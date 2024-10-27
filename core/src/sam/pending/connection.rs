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
    error::{ConnectionError, Error},
    runtime::Runtime,
    sam::{
        parser::{SamCommand, SamVersion, SessionKind},
        socket::SamSocket,
    },
};

use futures::{future::BoxFuture, FutureExt, StreamExt};
use hashbrown::HashMap;

use alloc::{boxed::Box, format, string::String, sync::Arc};
use core::{
    fmt,
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::pending::connection";

/// Minimum supported version of SAMv3.
const MIN_SAMV3_VERSION: SamVersion = SamVersion::V31;

/// Maximum supported version of SAMv3.
const MAX_SAMV3_VERSION: SamVersion = SamVersion::V33;

/// Keep-alive timeout.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// SAMv3 connection kind.
pub enum ConnectionKind<R: Runtime> {
    /// Create new session.
    Session {
        /// Session ID, generated by the client.
        session_id: Arc<str>,

        /// SAMv3 socket associated with the session.
        socket: SamSocket<R>,

        /// Negotiated version.
        version: SamVersion,

        /// Session kind.
        session_kind: SessionKind,

        /// Session options.
        options: HashMap<String, String>,
    },

    /// Open virtual stream to `destination` over this connection.
    Stream {
        /// Session ID, generated by the client.
        session_id: Arc<str>,

        /// SAMv3 socket associated with the outbound stream.
        socket: SamSocket<R>,

        /// Negotiated version.
        version: SamVersion,

        /// Destination.
        destination: String,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Accept inbond virtual stream over this connection.
    Accept {
        /// SAMv3 socket associated with the inbound stream.
        socket: SamSocket<R>,

        /// Negotiated version.
        version: SamVersion,

        /// Options.
        options: HashMap<String, String>,
    },

    /// Forward incoming virtual streams to a TCP listener listening to `port`.
    Forward {
        /// SAMv3 socket associated with forwarding.
        socket: SamSocket<R>,

        /// Negotiated version.
        version: SamVersion,

        /// Port which the TCP listener is listening.
        port: u16,
    },
}

impl<R: Runtime> fmt::Debug for ConnectionKind<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session {
                version,
                session_id,
                session_kind,
                options,
                ..
            } => f
                .debug_struct("ConnectionKind::Session")
                .field("version", &version)
                .field("session_id", &session_id)
                .field("session_kind", &session_kind)
                .field("options", &options)
                .finish_non_exhaustive(),
            Self::Stream {
                version,
                destination,
                options,
                ..
            } => f.debug_struct("ConnectionKind::Stream").finish_non_exhaustive(),
            Self::Accept { .. } => f.debug_struct("ConnectionKind::Accept").finish_non_exhaustive(),
            Self::Forward { .. } =>
                f.debug_struct("ConnectionKind::Forward").finish_non_exhaustive(),
        }
    }
}

/// Connection state.
///
/// Connection starts by the client and server agreeing on a SAMv3 version after which the client
/// sends one of four commands:
///  - `SESSION CREATE`
///  - `STREAM CONNECT`
///  - `STREAM ACCEPT`
///  - `STREAM FORWARD`
///
/// [`PendingSamConnection`] doesn't validate the command, apart from checking that it's a valid
/// SAMv3 command and leaves the validation of the command with respect to the overall connection
/// state to `SamServer` which ensures that for stream-related commands, there exists an active
/// session.
enum PendingConnectionState<R: Runtime> {
    /// Awaiting handshake from client.
    AwaitingHandshake {
        /// Socket used to read SAMv3 commands from client.
        socket: SamSocket<R>,
    },

    /// Session has been handshaked.
    Handshaked {
        /// Socket used to read SAMv3 commands from client.
        socket: SamSocket<R>,

        /// Negotiated SAMv3 version.
        version: SamVersion,
    },

    /// Connection state has been poisoned.
    Poisoned,
}

/// Pending SAMv3 connection.
///
/// Session can be one of four kinds:
///  - new session
///  - new outbound virtual stream
///  - new inbound virtual stream
///  - forwarding request
///
/// The last three kinds require there to be an active session.
pub struct PendingSamConnection<R: Runtime> {
    /// Connection state.
    state: PendingConnectionState<R>,

    /// Keep-alive timer.
    keep_alive_timer: BoxFuture<'static, ()>,
}

impl<R: Runtime> PendingSamConnection<R> {
    /// Create new [`PendingSamConnection`].
    pub fn new(stream: R::TcpStream) -> Self {
        Self {
            state: PendingConnectionState::AwaitingHandshake {
                socket: SamSocket::new(stream),
            },
            keep_alive_timer: Box::pin(R::delay(KEEP_ALIVE_TIMEOUT)),
        }
    }
}

impl<R: Runtime> Future for PendingSamConnection<R> {
    type Output = crate::Result<ConnectionKind<R>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match mem::replace(&mut self.state, PendingConnectionState::Poisoned) {
                PendingConnectionState::AwaitingHandshake { mut socket } => match socket
                    .poll_next_unpin(cx)
                {
                    Poll::Pending => {
                        self.state = PendingConnectionState::AwaitingHandshake { socket };
                        break;
                    }
                    Poll::Ready(None) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            "client closed socket",
                        );
                        return Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed)));
                    }
                    Poll::Ready(Some(SamCommand::Hello { min, max })) => {
                        // default to client's maximum supported version and if they didn't provide
                        // a version, default to server's maximum supported version which is SAMv3.3
                        let version = max.unwrap_or(SamVersion::V33);

                        tracing::debug!(
                            target: LOG_TARGET,
                            ?version,
                            "client connected"
                        );

                        socket.send_message(
                            format!("HELLO REPLY RESULT=OK VERSION={version}\n")
                                .as_bytes()
                                .to_vec(),
                        );
                        self.state = PendingConnectionState::Handshaked { version, socket };

                        // reset keep-alive timeout so the client has another 10 seconds to send the
                        // next command before the connection is closed
                        self.keep_alive_timer = Box::pin(R::delay(KEEP_ALIVE_TIMEOUT));
                    }
                    Poll::Ready(Some(command)) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?command,
                            "received an unexpected command, expected `HELLO`",
                        );
                        return Poll::Ready(Err(Error::InvalidState));
                    }
                },
                PendingConnectionState::Handshaked {
                    mut socket,
                    version,
                } => match socket.poll_next_unpin(cx) {
                    Poll::Pending => {
                        self.state = PendingConnectionState::Handshaked { socket, version };
                        break;
                    }
                    Poll::Ready(None) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            "client closed socket",
                        );
                        return Poll::Ready(Err(Error::Connection(ConnectionError::SocketClosed)));
                    }
                    Poll::Ready(Some(SamCommand::CreateSession {
                        session_id,
                        session_kind,
                        options,
                    })) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            %session_id,
                            ?session_kind,
                            "create session"
                        );

                        return Poll::Ready(Ok(ConnectionKind::Session {
                            session_id: Arc::from(session_id),
                            socket,
                            version,
                            session_kind,
                            options,
                        }));
                    }
                    Poll::Ready(Some(SamCommand::Connect {
                        session_id,
                        destination,
                        options,
                    })) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            %session_id,
                            "connect to destination"
                        );

                        return Poll::Ready(Ok(ConnectionKind::Stream {
                            session_id: Arc::from(session_id),
                            socket,
                            version,
                            destination,
                            options,
                        }));
                    }
                    Poll::Ready(Some(command)) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?command,
                            "received an unexpected command, expected `SESSION`/`STREAM`",
                        );
                        return Poll::Ready(Err(Error::InvalidState));
                    }
                },
                PendingConnectionState::Poisoned => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        "pending connection state has been poisoned",
                    );
                    debug_assert!(false);
                    return Poll::Ready(Err(Error::InvalidState));
                }
            }
        }

        if let Poll::Ready(_) = self.keep_alive_timer.poll_unpin(cx) {
            tracing::debug!(
                target: LOG_TARGET,
                "keep-alive timer expired, closing connection",
            );

            return Poll::Ready(Err(Error::Connection(ConnectionError::KeepAliveTimeout)));
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        mock::{MockRuntime, MockTcpStream},
        TcpStream as _,
    };
    use futures::StreamExt;
    use std::time::Duration;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn client_closes_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        stream1.unwrap().0.shutdown();

        match PendingSamConnection::<MockRuntime>::new(stream2.unwrap()).await {
            Err(Error::Connection(ConnectionError::SocketClosed)) => {}
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn keep_alive_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        match PendingSamConnection::<MockRuntime>::new(stream2.unwrap()).await {
            Err(Error::Connection(ConnectionError::KeepAliveTimeout)) => {}
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn keep_alive_timeout_after_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut connection = PendingSamConnection::<MockRuntime>::new(stream2.unwrap());
        let mut stream = stream1.unwrap().0;

        // send handshake
        stream.write_all(b"HELLO VERSION\n").await.unwrap();

        // poll pending connection until it's handshaked
        loop {
            futures::future::poll_fn(|cx| match connection.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                _ => panic!("invalid return value"),
            })
            .await;

            match connection.state {
                PendingConnectionState::Handshaked {
                    version: SamVersion::V33,
                    ..
                } => break,
                _ => {}
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // read and validate handshake response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response, "HELLO REPLY RESULT=OK VERSION=3.3\n");

        // verify connection times out
        match connection.await {
            Err(Error::Connection(ConnectionError::KeepAliveTimeout)) => {}
            _ => panic!("invalid result"),
        }
    }

    #[tokio::test]
    async fn client_requests_no_version() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut connection = PendingSamConnection::<MockRuntime>::new(stream2.unwrap());
        let mut stream = stream1.unwrap().0;

        // send handshake
        stream.write_all(b"HELLO VERSION\n").await.unwrap();

        // poll pending connection until it's handshaked
        loop {
            futures::future::poll_fn(|cx| match connection.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                _ => panic!("invalid return value"),
            })
            .await;

            match connection.state {
                PendingConnectionState::Handshaked {
                    version: SamVersion::V33,
                    ..
                } => break,
                _ => {}
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // read and validate handshake response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response, "HELLO REPLY RESULT=OK VERSION=3.3\n");
    }

    #[tokio::test]
    async fn client_requests_max_version() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut connection = PendingSamConnection::<MockRuntime>::new(stream2.unwrap());
        let mut stream = stream1.unwrap().0;

        // send handshake
        stream.write_all(b"HELLO VERSION MAX=3.2\n").await.unwrap();

        // poll pending connection until it's handshaked
        loop {
            futures::future::poll_fn(|cx| match connection.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                _ => panic!("invalid return value"),
            })
            .await;

            match connection.state {
                PendingConnectionState::Handshaked {
                    version: SamVersion::V32,
                    ..
                } => break,
                _ => {}
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // read and validate handshake response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response, "HELLO REPLY RESULT=OK VERSION=3.2\n");
    }

    #[tokio::test]
    async fn client_requests_min_version() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut connection = PendingSamConnection::<MockRuntime>::new(stream2.unwrap());
        let mut stream = stream1.unwrap().0;

        // send handshake
        stream.write_all(b"HELLO VERSION MIN=3.1\n").await.unwrap();

        // poll pending connection until it's handshaked
        loop {
            futures::future::poll_fn(|cx| match connection.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                _ => panic!("invalid return value"),
            })
            .await;

            match connection.state {
                PendingConnectionState::Handshaked {
                    version: SamVersion::V33,
                    ..
                } => break,
                _ => {}
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // read and validate handshake response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response, "HELLO REPLY RESULT=OK VERSION=3.3\n");
    }

    #[tokio::test]
    async fn session_create() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut connection = PendingSamConnection::<MockRuntime>::new(stream2.unwrap());
        let mut stream = stream1.unwrap().0;

        // send handshake
        stream.write_all(b"HELLO VERSION\n").await.unwrap();

        // poll pending connection until it's handshaked
        loop {
            futures::future::poll_fn(|cx| match connection.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(()),
                _ => panic!("invalid return value"),
            })
            .await;

            match connection.state {
                PendingConnectionState::Handshaked {
                    version: SamVersion::V33,
                    ..
                } => break,
                _ => {}
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // read and validate handshake response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.unwrap();

        assert_eq!(response, "HELLO REPLY RESULT=OK VERSION=3.3\n");

        // send handshake
        let mut stream = reader.into_inner();
        stream
            .write_all(b"SESSION CREATE STYLE=STREAM ID=test DESTINATION=TRANSIENT\n")
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(5), connection).await.unwrap() {
            Ok(ConnectionKind::Session {
                session_id,
                version: SamVersion::V33,
                session_kind: SessionKind::Stream,
                options,
                ..
            }) => {
                assert_eq!(&*session_id, "test");
            }
            Ok(kind) => panic!("invalid connection kind: {kind:?}"),
            Err(error) => panic!("failed to create session: {error:?}"),
        }
    }

    #[tokio::test]
    async fn send_sesssion_create_before_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(listener.accept(), MockTcpStream::connect(address));

        let mut connection = PendingSamConnection::<MockRuntime>::new(stream2.unwrap());
        let mut stream = stream1.unwrap().0;

        stream
            .write_all(b"SESSION CREATE STYLE=STREAM ID=test DESTINATION=TRANSIENT\n")
            .await
            .unwrap();

        match tokio::time::timeout(Duration::from_secs(5), connection).await.unwrap() {
            Err(Error::InvalidState) => {}
            Ok(kind) => panic!("session succeeded: {kind:?}"),
            Err(error) => panic!("invalid error: {error:?}"),
        }
    }
}
