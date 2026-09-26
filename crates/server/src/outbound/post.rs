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
//! # No redirects, and response bodies are bounded
//!
//! A 3xx is a failure, for the reason [`super::jwks`] gives: following one
//! means a new origin that has not been through the guard.
//!
//! A delivery caller may discard a successful response, while management and
//! polling callers parse a bounded success body. A *refusal* is different:
//! RFC 8935 §2.3 defines a JSON object with an `err` code the transmitter
//! acts on — `invalid_key` says the receiver could not use this server's
//! signing key. The first [`MAX_RESPONSE_BYTES`] of a refusal are kept and
//! handed to the caller, still as bytes.
//!
//! They stay bytes on purpose. They are a string an outsider chose, at a URL
//! another party configured, and the only thing entitled to turn them into
//! something this deployment stores is the parser that owns the specification
//! — [`asterius_ssf::push::ReceiverError::parse`], which maps the code onto a
//! closed set and bounds the free text. Nothing in this module renders them,
//! and [`PostError`]'s `Display` still names a host and a status and nothing
//! else.

use crate::outbound::jwks::{FetchError, HttpsClientUrlFetcher, TOTAL_TIMEOUT, vetted_addresses};
use crate::outbound::ssrf::{self, Target};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_LANGUAGE, CONTENT_TYPE, HOST, HeaderValue,
    USER_AGENT,
};
use hyper_util::rt::TokioIo;

/// The most bytes this server will send in one delivery.
///
/// A logout token is a JWT and an SSF event is a JWT; both are small, and a
/// megabyte of anything here would mean something upstream built a payload out
/// of unbounded input. Refusing before the socket is opened turns that into a
/// dead letter with a reason rather than a long upload.
pub const MAX_REQUEST_BYTES: usize = 128 * 1024;

/// The default response limit, and the limit on every refusal body.
///
/// It bounds two things: how long a receiver can hold the connection by
/// answering slowly and forever, and how much of a refusal is handed to the
/// caller that parses it (RFC 8935 §2.3). Public because that second bound is
/// part of what a caller is promised.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024;

/// A single SSF SET may itself fill the 8 KiB receiver limit. RFC 8936 adds
/// a JSON `sets` map, its JTI key, and `moreAvailable` around that SET.
/// Poll success responses get room for that envelope, but remain bounded.
const MAX_POLL_RESPONSE_BYTES: usize = 12 * 1024;

/// A bounded successful HTTP answer for protocols whose response has meaning.
///
/// The body may be a third party's data or contain an identifier. It is never
/// included in `Debug`, tracing, or [`PostError`]'s display text.
pub struct PostResponse {
    /// HTTP status returned by the receiver.
    pub status: u16,
    /// At most [`MAX_RESPONSE_BYTES`], or `MAX_POLL_RESPONSE_BYTES` for a
    /// successful SSF poll response, from the response body.
    pub body: Vec<u8>,
    /// Content type, when present and a valid HTTP header string.
    pub content_type: Option<String>,
    /// Cache policy, when present and a valid HTTP header string.
    pub cache_control: Option<String>,
    /// Whether more body bytes existed beyond the returned bound.
    pub truncated: bool,
}

impl std::fmt::Debug for PostResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("content_type_present", &self.content_type.is_some())
            .field("cache_control_present", &self.cache_control.is_some())
            .field("truncated", &self.truncated)
            .finish()
    }
}

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
        /// The first [`MAX_RESPONSE_BYTES`] of what it said, unparsed.
        ///
        /// Present so that RFC 8935 §2.3's error object can be read by the
        /// caller that owns that specification. Deliberately not part of
        /// `Display`: these bytes are a third party's, and nothing renders
        /// them until a parser has reduced them to a closed set.
        body: Vec<u8>,
    },
    /// A header value this server was asked to send is not one HTTP can carry.
    ///
    /// The only header whose value comes from outside this binary is the
    /// `Authorization` a push receiver registered (SSF 1.0 §6.1.1), and a
    /// stream holding one that cannot be sent is a misconfiguration rather
    /// than a receiver having a bad minute.
    #[error("the configured {header} header is not a value HTTP can carry")]
    BadHeader {
        /// Which header, as a constant of this binary — never the value.
        header: &'static str,
    },
}

/// What a delivery sends beside the body.
///
/// A struct rather than four arguments because two of the three are optional
/// and a call site with `None, None` says nothing about which is which.
#[derive(Clone, Copy)]
pub struct PostRequest<'a> {
    /// The body's media type.
    pub content_type: &'a str,
    /// What the transmitter will read back, if the protocol defines an answer.
    pub accept: Option<&'a str>,
    /// Language of an RFC 8936 `setErrs` description, when one is sent.
    pub content_language: Option<&'a str>,
    /// The `Authorization` header value the receiver registered, if any.
    ///
    /// SSF 1.0 §6.1.1: "the transmitter MUST send this value in every
    /// request". It is the receiver's credential, so it is never logged and
    /// never part of an error.
    pub authorization: Option<&'a str>,
}

/// Written by hand so that the credential is reported as present or absent and
/// never as itself. A derived `Debug` would put a receiver's bearer token in
/// the first `tracing` field anybody adds.
impl std::fmt::Debug for PostRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostRequest")
            .field("content_type", &self.content_type)
            .field("accept", &self.accept)
            .field("content_language", &self.content_language)
            .field("authorization", &self.authorization.map(|_| "<redacted>"))
            .finish()
    }
}

impl<'a> PostRequest<'a> {
    /// A delivery that sends only a media type, as back-channel logout does.
    #[must_use]
    pub const fn of(content_type: &'a str) -> Self {
        Self {
            content_type,
            accept: None,
            content_language: None,
            authorization: None,
        }
    }

    /// The same delivery, saying what it will read back.
    #[must_use]
    pub const fn accepting(mut self, accept: &'a str) -> Self {
        self.accept = Some(accept);
        self
    }

    /// Label the language of a request's human-readable error descriptions.
    #[must_use]
    pub const fn with_content_language(mut self, language: &'a str) -> Self {
        self.content_language = Some(language);
        self
    }

    /// The same delivery, authenticated as the receiver asked.
    #[must_use]
    pub const fn authorized_by(mut self, authorization: Option<&'a str>) -> Self {
        self.authorization = authorization;
        self
    }
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
            Self::TooLarge { .. } | Self::BadHeader { .. } => true,
            Self::Refused { status, .. } => *status >= 400 && *status < 500 && *status != 429,
            Self::Reach(_) => false,
        }
    }

    /// The status the receiver answered with, where one was read.
    ///
    /// `None` for a failure that never got an answer — a refused connection, a
    /// timeout, a body this server would not send.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Refused { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// What the receiver said, unparsed, where it said anything.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        match self {
            Self::Refused { body, .. } => body,
            _ => &[],
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
        self.post_with(url, PostRequest::of(content_type), body)
            .await
    }

    /// The same delivery, with the headers a protocol asks for.
    ///
    /// RFC 8935 §2.1 wants an `Accept`, and SSF 1.0 §6.1.1 obliges the
    /// transmitter to present the receiver's `authorization_header` on every
    /// request. Both are per-delivery values, so they are arguments rather
    /// than fields of the poster: one process has one poster and many streams.
    ///
    /// # Errors
    ///
    /// [`PostError`], whose `is_permanent` says whether a retry is worth an
    /// attempt and whose `body` carries a refusal's bytes for the caller that
    /// owns the specification defining them.
    pub async fn post_with(
        &self,
        url: &str,
        request: PostRequest<'_>,
        body: &[u8],
    ) -> Result<u16, PostError> {
        self.post_with_response(url, request, body)
            .await
            .map(|response| response.status)
    }

    /// Deliver a request and return bounded success metadata and body.
    ///
    /// Used by protocols such as Provider Commands where an HTTP 200 alone
    /// does not prove that the receiver acted on the intended account.
    ///
    /// # Errors
    ///
    /// Returns [`PostError`] for unsafe destinations or failed delivery.
    pub async fn post_with_response(
        &self,
        url: &str,
        request: PostRequest<'_>,
        body: &[u8],
    ) -> Result<PostResponse, PostError> {
        self.post_with_response_bound(url, request, body, MAX_RESPONSE_BYTES)
            .await
    }

    /// Read one bounded RFC 8936 poll response, including the JSON envelope
    /// around a receiver-sized SET. Refusal bodies retain the usual 8 KiB cap.
    ///
    /// # Errors
    ///
    /// Returns [`PostError`] for unsafe destinations or failed delivery.
    pub async fn post_with_poll_response(
        &self,
        url: &str,
        request: PostRequest<'_>,
        body: &[u8],
    ) -> Result<PostResponse, PostError> {
        self.post_with_response_bound(url, request, body, MAX_POLL_RESPONSE_BYTES)
            .await
    }

    async fn post_with_response_bound(
        &self,
        url: &str,
        request: PostRequest<'_>,
        body: &[u8],
        response_bound: usize,
    ) -> Result<PostResponse, PostError> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(PostError::TooLarge {
                size: body.len(),
                limit: MAX_REQUEST_BYTES,
            });
        }

        match tokio::time::timeout(
            TOTAL_TIMEOUT,
            self.send(url, request, body, hyper::Method::POST, response_bound),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(PostError::Reach(FetchError::TimedOut {
                host: ssrf::check_url(url).map_or_else(|_| "the URL".to_owned(), |t| t.host),
            })),
        }
    }

    /// Reads a bounded management response with the same SSRF, TLS, redirect,
    /// DNS and timeout rules as a POST. The OAuth credential remains a
    /// sensitive header and is not included in errors or `Debug` output.
    pub async fn get_with_response(
        &self,
        url: &str,
        authorization: &str,
    ) -> Result<PostResponse, PostError> {
        let request = PostRequest::of("")
            .accepting("application/json")
            .authorized_by(Some(authorization));
        match tokio::time::timeout(
            TOTAL_TIMEOUT,
            self.send(url, request, &[], hyper::Method::GET, MAX_RESPONSE_BYTES),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(PostError::Reach(FetchError::TimedOut {
                host: ssrf::check_url(url).map_or_else(|_| "the URL".to_owned(), |t| t.host),
            })),
        }
    }

    /// Deletes a pinned management resource through the same guarded HTTPS
    /// path. The caller supplies the authenticated, fully scoped URL and
    /// checks the returned status before changing local state.
    pub async fn delete_with_response(
        &self,
        url: &str,
        authorization: &str,
    ) -> Result<PostResponse, PostError> {
        let request = PostRequest::of("").authorized_by(Some(authorization));
        match tokio::time::timeout(
            TOTAL_TIMEOUT,
            self.send(url, request, &[], hyper::Method::DELETE, MAX_RESPONSE_BYTES),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(PostError::Reach(FetchError::TimedOut {
                host: ssrf::check_url(url).map_or_else(|_| "the URL".to_owned(), |t| t.host),
            })),
        }
    }

    /// The exchange, minus the timeout that wraps it.
    async fn send(
        &self,
        url: &str,
        request: PostRequest<'_>,
        body: &[u8],
        method: hyper::Method,
        response_bound: usize,
    ) -> Result<PostResponse, PostError> {
        let target = ssrf::check_url(url).map_err(FetchError::from)?;
        let addresses = vetted_addresses(&target).await?;
        let stream = self.connections.connect(&target, &addresses).await?;
        exchange(&target, request, body, method, stream, response_bound).await
    }
}

/// Sends the request and reads just enough of the answer to know the verdict.
async fn exchange(
    target: &Target,
    request: PostRequest<'_>,
    body: &[u8],
    method: hyper::Method,
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    response_bound: usize,
) -> Result<PostResponse, PostError> {
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

    let mut builder = hyper::Request::builder()
        .method(method.clone())
        .uri(&target.request_target)
        .header(HOST, &target.authority)
        .header(USER_AGENT, format!("asterius/{}", crate::VERSION))
        // One request per connection, as in `super::jwks`: nothing here reuses
        // it, and saying so lets the receiver close rather than hold a socket.
        .header(hyper::header::CONNECTION, "close");
    if method == hyper::Method::POST {
        builder = builder.header(CONTENT_TYPE, request.content_type);
    }
    if let Some(accept) = request.accept {
        builder = builder.header(ACCEPT, accept);
    }
    if let Some(language) = request.content_language {
        builder = builder.header(CONTENT_LANGUAGE, language);
    }
    if let Some(authorization) = request.authorization {
        // Built rather than pushed through the builder's error, so that a
        // stored credential HTTP cannot carry is named as what it is instead
        // of becoming the same "the exchange failed" a broken socket produces.
        // `from_str` is what rejects a value with a newline in it, which is
        // the header-injection case.
        let value = HeaderValue::from_str(authorization).map_err(|_| PostError::BadHeader {
            header: "Authorization",
        })?;
        // The one header value that is a credential: marking it sensitive
        // keeps it out of hyper's own debug output.
        let mut value = value;
        value.set_sensitive(true);
        builder = builder.header(AUTHORIZATION, value);
    }
    let request = builder
        .body(Full::<Bytes>::new(Bytes::copy_from_slice(body)))
        .map_err(|_| failed())?;

    let response = sender.send_request(request).await.map_err(|_| failed())?;
    let status = response.status();
    // A refused delivery is only diagnostic, so never retain a larger body.
    let response_bound = if status.is_success() {
        response_bound
    } else {
        MAX_RESPONSE_BYTES
    };
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 128)
        .map(str::to_owned);
    let cache_control = response
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 128)
        .map(str::to_owned);

    // Read to a bound rather than to the end. A receiver that answers and
    // then never finishes would otherwise keep the connection until timeout.
    let mut kept: Vec<u8> = Vec::new();
    let mut incoming = response.into_body();
    let mut truncated = false;
    while let Some(next) = incoming.frame().await {
        let Ok(frame) = next else {
            pump.abort();
            return Err(failed());
        };
        if let Some(chunk) = frame.data_ref() {
            let room = response_bound - kept.len();
            if chunk.len() > room {
                kept.extend_from_slice(&chunk[..room]);
                truncated = true;
                break;
            }
            kept.extend_from_slice(chunk);
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
            body: kept,
        });
    }
    Ok(PostResponse {
        status: status.as_u16(),
        body: kept,
        content_type,
        cache_control,
        truncated,
    })
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
                status: 400,
                body: Vec::new()
            }
            .is_permanent()
        );
        assert!(
            !PostError::Refused {
                host: host.clone(),
                status: 503,
                body: Vec::new()
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
            body: Vec::new(),
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
            body: Vec::new(),
        };

        // Act
        let rendered = refused.to_string();

        // Assert
        assert_eq!(rendered, "rp.example answered 502");
    }

    /// A receiver's refusal body is carried to the caller and never rendered
    /// by this module: RFC 8935 §2.3 defines it, and only the parser that owns
    /// that section may read it.
    #[test]
    fn a_refusal_carries_the_receivers_body_without_rendering_it() {
        // Arrange
        let refused = PostError::Refused {
            host: "rp.example".to_owned(),
            status: 400,
            body: br#"{"err":"invalid_key"}"#.to_vec(),
        };

        // Act
        let rendered = refused.to_string();

        // Assert
        assert_eq!(refused.body(), br#"{"err":"invalid_key"}"#);
        assert_eq!(refused.status(), Some(400));
        assert!(!rendered.contains("invalid_key"), "{rendered}");
    }

    /// A failure that never reached a receiver has no status and no body, so a
    /// caller cannot mistake "we did not get there" for "it said nothing".
    #[test]
    fn a_failure_with_no_answer_reports_neither_status_nor_body() {
        // Arrange
        let timed_out = PostError::Reach(FetchError::TimedOut {
            host: "rp.example".to_owned(),
        });

        // Act / Assert
        assert_eq!(timed_out.status(), None);
        assert!(timed_out.body().is_empty());
    }

    /// A stored `Authorization` that HTTP cannot carry is a misconfiguration,
    /// not a receiver having a bad minute: retrying it ten times would only
    /// delay the moment somebody is told.
    #[test]
    fn an_unsendable_authorization_header_is_permanent() {
        // Arrange
        let refused = PostError::BadHeader {
            header: "Authorization",
        };

        // Act / Assert
        assert!(refused.is_permanent());
        assert!(
            !refused.to_string().contains("Bearer"),
            "the value must never be rendered"
        );
    }

    /// The headers a protocol asks for are per-delivery, and a request that
    /// names none sends none — back-channel logout has no `Accept` and no
    /// credential of the receiver's.
    #[test]
    fn a_request_sends_only_the_headers_it_was_given() {
        // Arrange / Act
        let plain = PostRequest::of("application/jwt");
        let pushed = PostRequest::of("application/secevent+jwt")
            .accepting("application/json")
            .authorized_by(Some("Bearer t"));

        // Assert
        assert_eq!(plain.accept, None);
        assert_eq!(plain.authorization, None);
        assert_eq!(pushed.accept, Some("application/json"));
        assert_eq!(pushed.authorization, Some("Bearer t"));
    }

    /// A credential never renders itself, wherever it is written: this struct
    /// is in a `tracing` field or a `Debug` line sooner or later.
    #[test]
    fn a_request_does_not_render_its_credential() {
        // Arrange
        let request =
            PostRequest::of("application/secevent+jwt").authorized_by(Some("Bearer secret-value"));

        // Act
        let rendered = format!("{request:?}");

        // Assert
        assert!(!rendered.contains("secret-value"), "{rendered}");
    }
}
