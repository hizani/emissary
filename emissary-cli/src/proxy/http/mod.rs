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

use crate::{config::HttpProxyConfig, proxy::http::error::HttpError};

use futures::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use yosemite::{style, Session, SessionOptions, Stream};

use std::{sync::LazyLock, time::Duration};

mod error;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::proxy::http";

/// Illegal HTTP headers that get removed from the inbound HTTP request.
static ILLEGAL: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    Vec::from_iter([
        "accept",
        "referer",
        "x-requested-with",
        "via",
        "from",
        "forwarded",
        "dnt",
        "x-forwarded",
        "proxy-",
    ])
});

/// Parsed request.
#[derive(Debug)]
struct Request {
    /// TCP stream.
    stream: TcpStream,

    /// Host.
    host: String,

    /// Serialized request.
    request: Vec<u8>,
}

/// HTTP proxy.
pub struct HttpProxy {
    // TCP listener.
    listener: TcpListener,

    /// Inbound requests.
    requests: JoinSet<Option<Request>>,

    /// Outbound responses.
    responses: JoinSet<anyhow::Result<()>>,

    /// SAMv3 streaming session for the HTTP proxy.
    session: Session<style::Stream>,
}

impl HttpProxy {
    /// Create new [`HttpProxy`].
    pub async fn new(config: HttpProxyConfig, samv3_tcp_port: u16) -> crate::Result<Self> {
        tracing::info!(
            target: LOG_TARGET,
            host = %config.host,
            port = %config.port,
            "starting http proxy",
        );

        Ok(Self {
            listener: TcpListener::bind(format!("{}:{}", config.host, config.port)).await?,
            requests: JoinSet::new(),
            responses: JoinSet::new(),
            session: Session::<style::Stream>::new(SessionOptions {
                publish: false,
                samv3_tcp_port,
                nickname: "http-proxy".to_string(),
                ..Default::default()
            })
            .await?,
        })
    }

    /// Create HTTP 400 error response.
    fn create_http_error_response(error: &str) -> String {
        let status_line = "HTTP/1.1 400 Bad Request";
        let headers = "Content-Type: text/html; charset=UTF-8";
        let body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>400 Bad Request</title>
            </head>
            <body>
                <h1>400 Bad Request</h1>
                <p>{error}</p>
            </body>
            </html>
        "#
        );

        // Combine status line, headers, and body
        format!(
            "{status_line}\r\n{headers}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// Parse request.
    fn parse_request(request: Vec<u8>) -> Result<(String, Vec<u8>), HttpError> {
        // parse request and create a new request with sanitized headers
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let body_start = req.parse(&request)?.unwrap();
        let method = match req.method {
            None => return Err(HttpError::MethodMissing),
            Some("GET") => "GET".to_string(),
            Some("POST") => "POST".to_string(),
            Some(method) => return Err(HttpError::MethodNotSupported(method.to_string())),
        };
        let host = match req.headers.iter().find(|header| header.name.to_lowercase() == "host") {
            Some(host) => {
                let host = std::str::from_utf8(&host.value).map_err(|_| HttpError::Malformed)?;
                let host = host.strip_prefix("www.").unwrap_or(host).to_string();

                if !host.ends_with(".i2p") {
                    tracing::warn!(
                        target: LOG_TARGET,
                        ?host,
                        "ignoring non-.i2p host",
                    );
                    return Err(HttpError::InvalidHost);
                }

                host
            }
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    "host missing",
                );
                return Err(HttpError::InvalidHost);
            }
        };
        let path = match url::Url::parse(&req.path.ok_or(HttpError::InvalidPath)?) {
            Ok(url) => match url.query() {
                Some(query) => format!("{}?{query}", url.path()),
                None => url.path().to_string(),
            },
            Err(_) => req.path.ok_or(HttpError::InvalidPath)?.to_string(),
        };

        tracing::trace!(
            target: LOG_TARGET,
            method = ?req.method,
            %host,
            num_headers = ?req.headers.len(),
            "inbound request",
        );

        let builder = req.headers.into_iter().fold(
            http::Request::builder().method(method.as_str()).uri(path),
            |builder, header| {
                if header.name.to_lowercase() == "user-agent" {
                    return builder.header("User-Agent", "MYOB/6.66 (AN/ON)");
                }

                if header.name.to_lowercase() == "accept-encoding" {
                    return builder.header(header.name, header.value);
                }

                if header.name.to_lowercase() == "connection" {
                    return builder.header(header.name, "close");
                }

                if ILLEGAL.iter().any(|illegal| header.name.to_lowercase().starts_with(illegal)) {
                    return builder;
                }

                builder.header(header.name, header.value)
            },
        );

        let request = if body_start > request.len() {
            builder.body(request[body_start..].to_vec())
        } else {
            builder.body(Vec::new())
        }
        .expect("to succeed");

        Ok((host, {
            // serialize request into a byte vector
            let (parts, body) = request.into_parts();
            let mut request = Vec::new();

            request.extend_from_slice(&format!("{} ", parts.method.to_string()).as_bytes());
            request.extend_from_slice(&format!("{} ", parts.uri.to_string()).as_bytes());
            request.extend_from_slice(&"HTTP/1.1\r\n".as_bytes());

            for (name, value) in parts.headers {
                if let (Some(name), value) = (name, value) {
                    request.extend_from_slice(&format!("{name}: ").as_bytes());
                    request.extend_from_slice(value.as_bytes());
                    request.extend_from_slice("\r\n".as_bytes());
                }
            }
            request.extend_from_slice("\r\n".as_bytes());
            request.extend_from_slice(&body);

            request
        }))
    }

    /// Read request from browser.
    ///
    /// Reads the full request received from browser, parses it, removes any "prohibited" headers
    /// and reconstructs a new HTTP request that needs to be send to the requested destination,
    /// specified in the `Host` field of the original request.
    async fn read_request(mut stream: TcpStream) -> Result<Request, (TcpStream, HttpError)> {
        let mut buffer = vec![0u8; 8192];
        let mut nread = 0usize;

        // read from `stream` until complete request has been received
        loop {
            nread += match stream.read(&mut buffer[nread..]).await {
                Err(error) => return Err((stream, HttpError::Io(error.kind()))),
                Ok(0) => return Err((stream, HttpError::Io(std::io::ErrorKind::BrokenPipe))),
                Ok(nread) => nread,
            };

            let mut headers = [httparse::EMPTY_HEADER; 64];
            match httparse::Request::new(&mut headers).parse(&buffer[..nread]) {
                Err(_) => return Err((stream, HttpError::Malformed)),
                Ok(request) if request.is_complete() => break,
                Ok(_) => {}
            }
        }

        // parse request and create a new request with sanitized headers
        match Self::parse_request(buffer[..nread].to_vec()) {
            Err(error) => Err((stream, error)),
            Ok((host, request)) => Ok(Request {
                stream,
                host,
                request,
            }),
        }
    }

    /// Send `request` to remote destination over `i2p_stream`, read the full HTTP response
    /// and send it to the browser.
    async fn send_response(
        mut stream: TcpStream,
        mut i2p_stream: Stream,
        request: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut buffer = vec![0u8; 2048];

        // write request and read from the stream until it is closed
        i2p_stream.write_all(&request).await?;

        loop {
            match i2p_stream.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    break;
                }
                Ok(nread) => {
                    stream.write_all(&buffer[..nread]).await?;
                }
            };
        }

        Ok(())
    }

    /// Run event loop of [`HttpProxy`].
    pub async fn run(mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                connection = self.listener.accept() => match connection {
                    Ok((stream, _)) => {
                        self.requests.spawn(async move {
                            match tokio::time::timeout(Duration::from_secs(10), Self::read_request(stream)).await {
                                Err(_) => None,
                                Ok(Ok(request)) => Some(request),
                                Ok(Err((mut stream, error))) => {
                                    tracing::debug!(
                                        target: LOG_TARGET,
                                        ?error,
                                        "failed to handle inbound http request",
                                    );

                                    let error = match error {
                                        HttpError::Io(_) => return None,
                                        HttpError::InvalidHost => "Only .i2p and .b32.i2p hosts are supported",
                                        _ => "Malformed request",
                                    };

                                    let response = Self::create_http_error_response(error);
                                    if let Err(error) = stream.write_all(&response.as_bytes()).await {
                                        tracing::debug!(
                                            target: LOG_TARGET,
                                            ?error,
                                            "failed to send error response to client",
                                        );
                                    }

                                    None
                                }
                            }
                        });
                    }
                    Err(error) => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to read from socket"
                        );
                    }
                },
                request = self.requests.join_next(), if !self.requests.is_empty() => match request {
                    Some(Ok(Some(request))) => match self.session.connect(&request.host).await {
                        Ok(stream) => {
                            self.responses.spawn(Self::send_response(request.stream, stream, request.request));
                        }
                        Err(error) => tracing::debug!(
                            target: LOG_TARGET,
                            ?error,
                            "failed to connect to destination",
                        ),
                    },
                    Some(Ok(None)) => {},
                    Some(Err(error)) => tracing::debug!(
                        target: LOG_TARGET,
                        ?error,
                        "failed to poll http request",
                    ),
                    None => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn make_connection() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (res1, res2) = tokio::join!(listener.accept(), TcpStream::connect(address));

        (res1.unwrap().0, res2.unwrap())
    }

    #[tokio::test]
    async fn get_accepted() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2
                .write_all(&"GET / HTTP/1.1\r\nHost: host.i2p\r\n\r\n".as_bytes())
                .await
                .unwrap();
        });

        let Request { host, request, .. } = HttpProxy::read_request(stream1).await.unwrap();
        assert_eq!(host.as_str(), "host.i2p");

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "host").unwrap().value,
            "host.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn get_full_path() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2
                .write_all(
                    &"GET http://www.host.i2p HTTP/1.1\r\nHost: www.host.i2p\r\n\r\n".as_bytes(),
                )
                .await
                .unwrap();
        });

        let Request { host, request, .. } = HttpProxy::read_request(stream1).await.unwrap();
        assert_eq!(host.as_str(), "host.i2p");

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "host").unwrap().value,
            "www.host.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn www_stripped_from_host() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2
                .write_all(&"GET / HTTP/1.1\r\nHost: www.host.i2p\r\n\r\n".as_bytes())
                .await
                .unwrap();
        });

        let Request { host, request, .. } = HttpProxy::read_request(stream1).await.unwrap();
        assert_eq!(host.as_str(), "host.i2p");

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "host").unwrap().value,
            "www.host.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn converted_to_relative_path() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2
                .write_all(&"GET http://www.host.i2p/topics/new-topic?query=1 HTTP/1.1\r\nHost: www.host.i2p\r\n\r\n".as_bytes())
                .await
                .unwrap();
        });

        let Request { host, request, .. } = HttpProxy::read_request(stream1).await.unwrap();
        assert_eq!(host.as_str(), "host.i2p");

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("GET"));
        assert_eq!(req.path, Some("/topics/new-topic?query=1"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "host").unwrap().value,
            "www.host.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn post_accepted() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2
                .write_all(
                    &"POST /upload HTTP/1.1\r\n\
                    Host: www.host.i2p\r\n\
                    Content-Type: text/plain\r\n\
                    Content-Length: 12\r\n\r\n\
                    hello, world"
                        .as_bytes(),
                )
                .await
                .unwrap();
        });

        let Request { host, request, .. } = HttpProxy::read_request(stream1).await.unwrap();
        assert_eq!(host.as_str(), "host.i2p");

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let _body_start = req.parse(&request).unwrap().unwrap();

        assert_eq!(req.method, Some("POST"));
        assert_eq!(req.path, Some("/upload"));
        assert_eq!(
            req.headers.iter().find(|header| header.name == "host").unwrap().value,
            "www.host.i2p".as_bytes(),
        );
    }

    #[tokio::test]
    async fn connect_reject() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2
                .write_all(
                    "CONNECT www.host.i2p:443 HTTP/1.1\r\nHost: www.host.i2p:443\r\n\r\n"
                        .as_bytes(),
                )
                .await
                .unwrap();
        });

        assert_eq!(
            HttpProxy::read_request(stream1).await.unwrap_err().1,
            HttpError::MethodNotSupported("CONNECT".to_string())
        );
    }

    #[tokio::test]
    async fn non_i2p_host() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2
                .write_all(&"GET / HTTP/1.1\r\nHost: host.com\r\n\r\n".as_bytes())
                .await
                .unwrap();
        });

        assert_eq!(
            HttpProxy::read_request(stream1).await.unwrap_err().1,
            HttpError::InvalidHost,
        );
    }

    #[tokio::test]
    async fn read_partial_request() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2.write_all(&"GET / HTTP/1.1\r\nHost".as_bytes()).await.unwrap();
            stream2.shutdown().await.unwrap();
        });

        assert!(std::matches!(
            HttpProxy::read_request(stream1).await.unwrap_err().1,
            HttpError::Io(_),
        ));
    }

    #[tokio::test]
    async fn invalid_request() {
        let (stream1, mut stream2) = make_connection().await;

        tokio::spawn(async move {
            stream2.write_all(&"hello, world\r\n".as_bytes()).await.unwrap();
        });

        assert_eq!(
            HttpProxy::read_request(stream1).await.unwrap_err().1,
            HttpError::Malformed,
        );
    }
}
