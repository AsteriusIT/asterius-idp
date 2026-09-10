//! Posting to a URL a client registered, over a connection this server chose.
//!
//! The second thing this server does with a client-supplied URL. [`super::jwks`]
//! *reads* one — a `jwks_uri`, a `sector_identifier_uri` — and this *writes* to
//! one: a `backchannel_logout_uri` (OIDC Back-Channel Logout 1.0 §2.5), an SSF
//! push delivery endpoint (RFC 8935 §2), a CIBA `client_notification_endpoint`.
//!
//! ADR-0006 says every fetch of a client-supplied URL goes through one path,
//! and the direction of the body does not change any of the reasons. So this
//! module owns no rules of its own: [`super::ssrf`] still decides which URLs
//! and which addresses, and the TLS configuration, the connect and the
//! resolution are [`HttpsClientUrlFetcher`]'s, borrowed rather than copied.
//! What is new here is only what a request with a body has to say — a method,
//! a `Content-Type`, a `Content-Length` — and what an answer to one means.
//!
//! # A POST makes the guard matter more, not less
//!
//! An SSRF on a `GET` reads something the attacker should not have been able
//! to read. An SSRF on a `POST` *does* something: it delivers a body of the
//! attacker's choosing to an address of the attacker's choosing, from inside
//! the network the authorization server runs in. Cloud metadata services and
//! internal admin APIs are the usual examples, and both are one unguarded
//! `POST` away. The guard is the same guard; it is simply less forgiving of a
//! gap.
//!
//! # No redirects, and no response body
//!
//! A 3xx is a failure, for the reason [`super::jwks`] gives: following one
//! means a new origin that has not been through the guard. And the response
//! body is drained and discarded rather than returned. None of the three
//! protocols above define anything a receiver may say back that changes what
//! the transmitter does — a status code is the whole answer — and a body from
//! a client-nominated host is an attacker-controlled string that would end up
//! in a `last_error` column and then on an operator's screen.

use crate::outbound::jwks::{FetchError, HttpsClientUrlFetcher, TOTAL_TIMEOUT, vetted_addresses};
use crate::outbound::ssrf::{self, Target};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::header::{CONTENT_TYPE, HOST, USER_AGENT};
use hyper_util::rt::TokioIo;

/// The most bytes this server will send in one delivery.
///
/// A logout token is a JWT and an SSF event is a JWT; both are small, and a
/// megabyte of anything here would mean something upstream built a payload out
/// of unbounded input. Refusing before the socket is opened turns that into a
/// dead letter with a reason rather than a long upload.
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;

/// The most bytes read back before the connection is dropped.
///
/// The body is discarded either way; this only bounds how long a receiver can
/// hold the connection by answering slowly and forever.
const MAX_RESPONSE_BYTES: usize = 8 * 1024;

/// Why a delivery did not happen.
///
/// [`FetchError`] covers everything about *reaching* the host, and is reused
/// rather than re-spelt: the URL was refused, the name did not resolve, the
/// address is one this server does not reach, TLS failed, it timed out. What
/// is added here is the two things only a request with a body can go wrong at.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PostError {
    /// The host could not be reached, or the exchange failed.
    #[error(transparent)]
    Reach(#[from] FetchError),
    /// The body is larger than [`MAX_REQUEST_BYTES`].
    #[error("payload is {size} bytes, limit is {limit}")]
    TooLarge {
        /// How big it was.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The receiver answered, and did not accept.
    #[error("{host} answered {status}")]
    Refused {
        /// The host, never the URL: a delivery endpoint may carry a query
        /// parameter its owner treats as a secret, and this string is written
        /// to `outbox.last_error` and shown to an operator.
        host: String,
        /// The status code it answered with.
        status: u16,
    },
}

impl PostError {
    /// Whether trying again could plausibly work.
    ///
    /// A 4xx other than 429 is the receiver saying the request itself is
    /// wrong, and repeating it nine more times will not make it right; it
    /// spends the attempt budget and then dead-letters, which is the correct
    /// destination but a slow way to reach it. Everything else — a timeout, a
    /// 5xx, a refused connection, a 429 — is a receiver having a bad minute.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        match self {
            Self::TooLarge { .. } => true,
            Self::Refused { status, .. } => *status >= 400 && *status < 500 && *status != 429,
            Self::Reach(_) => false,
        }
    }
}

/// Posts to client-supplied URLs, subject to [`super::ssrf`].
///
/// Holds a [`HttpsClientUrlFetcher`] for its TLS configuration and its connect,
/// so a deployment has one set of trust anchors and one set of cipher suites
/// for everything it dials out to.
#[derive(Debug, Clone)]
pub struct HttpsPoster {
    connections: HttpsClientUrlFetcher,
}

impl HttpsPoster {
    /// Builds a poster over the process's outbound TLS configuration.
    ///
    /// # Errors
    ///
    /// Returns [`rustls::Error`] if the provider will not accept the cipher
    /// suite and version combination, which would be a build-time mistake.
    pub fn new() -> Result<Self, rustls::Error> {
        Ok(Self {
            connections: HttpsClientUrlFetcher::new()?,
        })
    }

    /// Wraps a fetcher that already exists, so the process holds one.
    #[must_use]
    pub const fn over(connections: HttpsClientUrlFetcher) -> Self {
        Self { connections }
    }

    /// Delivers `body` to `url` and returns the status it was accepted with.
    ///
    /// One timeout over the whole exchange, resolution included, for the
    /// reason [`super::jwks::HttpsClientUrlFetcher`] gives: a per-step timeout lets
    /// a receiver that is slow at every step hold the worker for the sum of
    /// them, and the worker's claim lease is what that has to stay under.
    ///
    /// # Errors
    ///
    /// [`PostError`], whose `is_permanent` says whether a retry is worth an
    /// attempt.
    pub async fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<u16, PostError> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(PostError::TooLarge {
                size: body.len(),
                limit: MAX_REQUEST_BYTES,
            });
        }

        match tokio::time::timeout(TOTAL_TIMEOUT, self.send(url, content_type, body)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(PostError::Reach(FetchError::TimedOut {
                host: ssrf::check_url(url).map_or_else(|_| "the URL".to_owned(), |t| t.host),
            })),
        }
    }

    /// The exchange, minus the timeout that wraps it.
    async fn send(&self, url: &str, content_type: &str, body: &[u8]) -> Result<u16, PostError> {
        let target = ssrf::check_url(url).map_err(FetchError::from)?;
        let addresses = vetted_addresses(&target).await?;
        let stream = self.connections.connect(&target, &addresses).await?;
        exchange(&target, content_type, body, stream).await
    }
}

/// Sends the request and reads just enough of the answer to know the verdict.
async fn exchange(
    target: &Target,
    content_type: &str,
    body: &[u8],
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<u16, PostError> {
    let failed = || {
        PostError::Reach(FetchError::Http {
            host: target.host.clone(),
        })
    };

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| failed())?;
    // Drives the socket while the request is in flight; it ends with the
    // response or when the timeout above drops the sender.
    let pump = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&target.request_target)
        .header(HOST, &target.authority)
        .header(CONTENT_TYPE, content_type)
        .header(USER_AGENT, format!("asterius/{}", crate::VERSION))
        // One request per connection, as in `super::jwks`: nothing here reuses
        // it, and saying so lets the receiver close rather than hold a socket.
        .header(hyper::header::CONNECTION, "close")
        .body(Full::<Bytes>::new(Bytes::copy_from_slice(body)))
        .map_err(|_| failed())?;

    let response = sender.send_request(request).await.map_err(|_| failed())?;
    let status = response.status();

    // Drained rather than read: a receiver that answers 200 and then never
    // finishes its body would otherwise keep the connection until the timeout,
    // and the bytes themselves are of no interest to anybody.
    let mut remaining = MAX_RESPONSE_BYTES;
    let mut incoming = response.into_body();
    while let Some(Ok(frame)) = incoming.frame().await {
        if let Some(chunk) = frame.data_ref() {
            remaining = remaining.saturating_sub(chunk.len());
            if remaining == 0 {
                break;
            }
        }
    }
    pump.abort();

    if status.is_redirection() {
        return Err(PostError::Reach(FetchError::Redirect {
            host: target.host.clone(),
            status: status.as_u16(),
        }));
    }
    if !status.is_success() {
        return Err(PostError::Refused {
            host: target.host.clone(),
            status: status.as_u16(),
        });
    }
    Ok(status.as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body this server built is bounded before a socket is opened. The
    /// check is on the *request*, so an oversized payload becomes a dead
    /// letter with a reason rather than a long upload to a third party.
    #[tokio::test]
    async fn an_oversized_body_is_refused_before_anything_is_dialled() {
        // Arrange
        let poster = HttpsPoster::new().expect("build a poster");
        let body = vec![b'x'; MAX_REQUEST_BYTES + 1];

        // Act
        let refused = poster
            .post("https://rp.example/logout", "application/jwt", &body)
            .await
            .expect_err("an oversized body must be refused");

        // Assert
        assert!(matches!(refused, PostError::TooLarge { .. }));
        assert!(refused.is_permanent());
    }

    /// The SSRF guard applies to a `POST` exactly as it does to a `GET`, and
    /// this is the case that matters most: a loopback address is where a
    /// deployment's own admin API lives.
    #[tokio::test]
    async fn a_loopback_destination_is_refused() {
        // Arrange
        let poster = HttpsPoster::new().expect("build a poster");

        // Act
        let refused = poster
            .post("https://127.0.0.1/logout", "application/jwt", b"{}")
            .await
            .expect_err("loopback must be refused");

        // Assert
        assert!(matches!(refused, PostError::Reach(FetchError::Url(_))));
    }

    /// A 400 means the request was wrong and will be wrong again; a 503 means
    /// the receiver is having a bad minute. Retrying the first nine more times
    /// only delays the dead letter it was always going to become.
    #[test]
    fn a_client_error_is_permanent_and_a_server_error_is_not() {
        // Arrange
        let host = "rp.example".to_owned();

        // Act / Assert
        assert!(
            PostError::Refused {
                host: host.clone(),
                status: 400
            }
            .is_permanent()
        );
        assert!(
            !PostError::Refused {
                host: host.clone(),
                status: 503
            }
            .is_permanent()
        );
    }

    /// 429 is the one 4xx that means "later", and treating it as permanent
    /// would dead-letter every delivery to a receiver that rate limits.
    #[test]
    fn too_many_requests_is_not_permanent() {
        // Arrange / Act
        let throttled = PostError::Refused {
            host: "rp.example".to_owned(),
            status: 429,
        };

        // Assert
        assert!(!throttled.is_permanent());
    }

    /// The host and the status, and nothing else. The URL may carry a query
    /// parameter its owner treats as a secret, and this string reaches
    /// `outbox.last_error` and an operator's screen.
    #[test]
    fn a_refusal_names_the_host_and_never_the_url() {
        // Arrange
        let refused = PostError::Refused {
            host: "rp.example".to_owned(),
            status: 502,
        };

        // Act
        let rendered = refused.to_string();

        // Assert
        assert_eq!(rendered, "rp.example answered 502");
    }
}
