//! Fetching a client's JWK Set, over a connection this server chose.
//!
//! The adapter behind [`asterius_domain::ports::JwksFetcher`]. It lives in the
//! composition root and nowhere else: `asterius-jose` parses JWK Sets and
//! caches them but cannot open a socket, which
//! [`scripts/check-layering.sh`](../../../../../scripts/check-layering.sh)
//! enforces by refusing it `hyper` — and which is right for a reason beyond
//! tidiness. Dereferencing a URL an attacker chose is a security decision with
//! its own surface: which addresses, which redirects, how many bytes, how long.
//! It belongs next to the socket, in one file, where it can be read whole.
//!
//! [`super::ssrf`] holds the rules and the reasoning about what they do and do
//! not stop. This module is the plumbing that obeys them, and its one
//! non-obvious line is the connect:
//!
//! ```text
//! TcpStream::connect(vetted_address)      // an address that passed the guard
//! ```
//!
//! rather than `connect((host, port))`, which would resolve the name a second
//! time and hand DNS rebinding the answer it wants.
//!
//! # The exchange
//!
//! One `GET`, HTTP/1.1, `Connection: close`, and no redirect is ever followed.
//!
//! Not following redirects is a decision rather than an omission. A redirect is
//! the cheapest way to defeat an SSRF guard: pass the check with a public
//! `Location`, then send the fetcher somewhere else — and "somewhere else" is a
//! new origin, a new name, a new set of addresses, all of which would have to
//! go back through the guard, with a hop counter to keep it from looping.
//! Nothing in OIDC Registration §2 or RFC 7517 §5 asks a JWK Set to be served
//! through a redirect, and a client that needs one can publish the final URL.
//! So a 3xx is a failure with its own message, and the operator is told why.

use crate::outbound::ssrf::{self, Target, UrlRefused};
use asterius_domain::DomainError;
use asterius_domain::ports::JwksFetcher;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONTENT_TYPE, HOST, USER_AGENT};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The most bytes read from a client's JWK Set endpoint.
///
/// Enforced while reading rather than afterwards, so a body that never ends
/// costs this much and stops. [`asterius_jose::MAX_JWK_SET_BYTES`] is the same
/// number checked again by the parser, because the parser is also reached from
/// storage.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// How long the TCP connection has to be established.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the whole fetch has, resolution and TLS included.
///
/// A client's key server is on the critical path of that client's
/// authentication, and a server that hangs must not hold a request open behind
/// it. Five seconds is the outer bound; the caching in
/// [`asterius_jose::ClientKeyCache`] is what stops it from being paid often.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

/// The most resolved addresses one host may offer before the answer is refused.
///
/// A resolver under an attacker's control can return as many records as it
/// likes, and every one of them is a check and possibly a connection attempt.
const MAX_ADDRESSES: usize = 16;

/// The most addresses actually connected to before giving up.
///
/// Every address has already passed the guard, so this is about work rather
/// than safety: it is a retry for a host whose first address is down, not a
/// scan.
const MAX_ATTEMPTS: usize = 2;

/// Media types a JWK Set may be served as.
///
/// `application/jwk-set+json` is what RFC 7517 §8.5 registers for a JWK Set;
/// `application/json` is what most of the ecosystem actually sends. Anything
/// else — `text/html` above all — is a login page, an error page, or a captive
/// portal, and parsing it would only produce a confusing failure later.
const JWK_SET_MEDIA_TYPES: [&str; 2] = ["application/jwk-set+json", "application/json"];

/// Why a JWK Set could not be fetched.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The URL is not one this server dereferences.
    #[error("refusing to fetch: {0}")]
    Url(#[from] UrlRefused),
    /// The host resolved to an address in a range this server does not reach.
    ///
    /// Refusing the *whole* fetch rather than skipping the address is
    /// deliberate: a name that answers with both a public and a private address
    /// is a rebinding attempt far more often than it is a multi-homed key
    /// server, and connecting to whichever address happened to pass would be
    /// exactly the behaviour that makes the guard defeatable.
    #[error("{host} resolves to {address}, which is {reason}")]
    Address {
        /// The name that resolved to it.
        host: String,
        /// The address.
        address: IpAddr,
        /// Which reserved range it falls in.
        reason: &'static str,
    },
    /// The host did not resolve, or resolved to nothing.
    #[error("cannot resolve {host}")]
    Resolve {
        /// The name.
        host: String,
    },
    /// The host offered more addresses than this server will consider.
    #[error("{host} resolves to more than {limit} addresses")]
    TooManyAddresses {
        /// The name.
        host: String,
        /// The limit.
        limit: usize,
    },
    /// Nothing answered on any vetted address.
    #[error("cannot connect to {host}")]
    Connect {
        /// The name.
        host: String,
    },
    /// The TLS handshake failed — an untrusted certificate, or a name mismatch.
    #[error("TLS handshake with {host} failed")]
    Tls {
        /// The name.
        host: String,
    },
    /// The HTTP exchange failed.
    #[error("HTTP exchange with {host} failed")]
    Http {
        /// The name.
        host: String,
    },
    /// A redirect, which is not followed.
    #[error("{host} answered {status}; redirects are not followed")]
    Redirect {
        /// The name.
        host: String,
        /// The status.
        status: u16,
    },
    /// Any other status than 200.
    #[error("{host} answered {status}")]
    Status {
        /// The name.
        host: String,
        /// The status.
        status: u16,
    },
    /// The response is not a JSON media type.
    #[error("{host} served {found:?}, not a JWK Set media type")]
    MediaType {
        /// The name.
        host: String,
        /// What the `Content-Type` said, or its absence.
        found: String,
    },
    /// The body is larger than [`MAX_BODY_BYTES`].
    #[error("{host} served more than {limit} bytes")]
    TooLarge {
        /// The name.
        host: String,
        /// The limit.
        limit: usize,
    },
    /// The fetch did not finish within [`TOTAL_TIMEOUT`].
    #[error("fetching from {host} timed out")]
    TimedOut {
        /// The name, or the URL when it was never taken apart.
        host: String,
    },
}

impl From<FetchError> for DomainError {
    /// A refusal is a statement about the client's registration; everything
    /// else is a dependency failing. The distinction is for an operator reading
    /// a log: [`asterius_jose::ClientKeyCache`] flattens both to "unavailable"
    /// before any of it could reach a client.
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::Url(_) | FetchError::Address { .. } => {
                Self::invalid("jwks_uri", error.to_string())
            }
            other => Self::Storage(Box::new(other)),
        }
    }
}

/// Fetches client JWK Sets over TLS, subject to [`super::ssrf`].
///
/// Holds a TLS configuration and nothing else: no connection pool, no keep-alive
/// across fetches. A pooled connection to a host chosen by a client is state
/// that outlives the request it was opened for, and the saving — one handshake
/// per client per cache TTL — is not worth reasoning about it.
#[derive(Clone)]
pub struct HttpsJwksFetcher {
    tls: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for HttpsJwksFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsJwksFetcher").finish_non_exhaustive()
    }
}

impl HttpsJwksFetcher {
    /// Builds a fetcher trusting the Mozilla root programme's certificate
    /// authorities.
    ///
    /// Compiled-in roots rather than the platform store: the platform store in
    /// a scratch container is empty, and a fetcher that silently trusts nothing
    /// — or silently trusts whatever an image happened to ship — is worse than
    /// one whose trust anchors are part of the build.
    ///
    /// The cipher suites and protocol versions are the listener's, from
    /// [`crate::http::tls`]. FAPI 2.0 SP §5.2.2 applies BCP 195 to
    /// server-to-server connections, and this is one: the direction of the
    /// connection does not change what a good TLS configuration is.
    ///
    /// # Errors
    ///
    /// Returns [`rustls::Error`] if the provider will not accept the cipher
    /// suite and version combination, which would be a build-time mistake
    /// rather than a runtime one.
    pub fn new() -> Result<Self, rustls::Error> {
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites: crate::http::tls::CIPHER_SUITES.to_vec(),
            ..rustls::crypto::aws_lc_rs::default_provider()
        });
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(crate::http::tls::PROTOCOL_VERSIONS)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Only HTTP/1.1 is offered. HTTP/2 to a server a client nominated would
        // mean multiplexing, flow control and server-chosen frame sizes on a
        // connection opened on an attacker's say-so, for a single small GET.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self { tls: Arc::new(tls) })
    }

    /// The fetch, minus the timeout that wraps it.
    async fn get(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let target = ssrf::check_url(url)?;
        let addresses = vetted_addresses(&target).await?;
        let stream = self.connect(&target, &addresses).await?;
        read_jwk_set(&target, stream).await
    }

    /// Opens a TLS connection to one of the vetted addresses.
    async fn connect(
        &self,
        target: &Target,
        addresses: &[SocketAddr],
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, FetchError> {
        let mut stream = None;
        for address in addresses.iter().take(MAX_ATTEMPTS) {
            // The address, not the name. Nothing here can resolve, so there is
            // no second answer for a rebinding attack to give — see the module
            // documentation in `super::ssrf`.
            if let Ok(Ok(connected)) =
                tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await
            {
                stream = Some(connected);
                break;
            }
        }
        let Some(stream) = stream else {
            return Err(FetchError::Connect {
                host: target.host.clone(),
            });
        };

        // The certificate is checked against the *name* the client registered,
        // not against the address we connected to. That is what keeps the
        // address check from weakening authentication: we choose where to
        // connect, and the certificate still has to belong to the host the
        // registration named.
        let name = ServerName::try_from(target.host.clone()).map_err(|_| FetchError::Tls {
            host: target.host.clone(),
        })?;
        TlsConnector::from(self.tls.clone())
            .connect(name, stream)
            .await
            .map_err(|_| FetchError::Tls {
                host: target.host.clone(),
            })
    }
}

/// Resolves a host and checks every address it answered with.
///
/// An IP literal never reaches the resolver — [`ssrf::check_url`] has already
/// passed judgement on it — so this is a lookup only when the host is a name.
async fn vetted_addresses(target: &Target) -> Result<Vec<SocketAddr>, FetchError> {
    if let Ok(literal) = target.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(literal, target.port)]);
    }

    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|_| FetchError::Resolve {
            host: target.host.clone(),
        })?
        .collect();

    if resolved.is_empty() {
        return Err(FetchError::Resolve {
            host: target.host.clone(),
        });
    }
    if resolved.len() > MAX_ADDRESSES {
        return Err(FetchError::TooManyAddresses {
            host: target.host.clone(),
            limit: MAX_ADDRESSES,
        });
    }
    for address in &resolved {
        if let Some(reason) = ssrf::why_refused(address.ip()) {
            return Err(FetchError::Address {
                host: target.host.clone(),
                address: address.ip(),
                reason,
            });
        }
    }
    Ok(resolved)
}

/// Sends the request and reads the answer, within the limits.
async fn read_jwk_set(
    target: &Target,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<Vec<u8>, FetchError> {
    let failed = || FetchError::Http {
        host: target.host.clone(),
    };

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| failed())?;
    // The connection future drives the socket while the request is in flight.
    // It ends when the response is complete or the timeout above drops the
    // sender, so it is not a task that outlives the fetch.
    let pump = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&target.request_target)
        .header(HOST, &target.authority)
        .header(ACCEPT, JWK_SET_MEDIA_TYPES.join(", "))
        .header(USER_AGENT, format!("asterius/{}", crate::VERSION))
        // One request per connection. Nothing here reuses it, and saying so
        // lets the other end close instead of holding a socket open.
        .header(hyper::header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|_| failed())?;

    let response = sender.send_request(request).await.map_err(|_| failed())?;
    let status = response.status();
    if status.is_redirection() {
        pump.abort();
        return Err(FetchError::Redirect {
            host: target.host.clone(),
            status: status.as_u16(),
        });
    }
    if status != hyper::StatusCode::OK {
        pump.abort();
        return Err(FetchError::Status {
            host: target.host.clone(),
            status: status.as_u16(),
        });
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if !is_jwk_set_media_type(&content_type) {
        pump.abort();
        return Err(FetchError::MediaType {
            host: target.host.clone(),
            found: content_type,
        });
    }

    // The body is read frame by frame with a running total, so a response that
    // never ends — or one whose `Content-Length` lied — stops at the cap rather
    // than after it.
    let mut body = response.into_body();
    let mut collected: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| failed())?;
        if let Some(chunk) = frame.data_ref() {
            if collected.len() + chunk.len() > MAX_BODY_BYTES {
                pump.abort();
                return Err(FetchError::TooLarge {
                    host: target.host.clone(),
                    limit: MAX_BODY_BYTES,
                });
            }
            collected.extend_from_slice(chunk);
        }
    }
    pump.abort();
    Ok(collected)
}

/// Whether a `Content-Type` names a media type a JWK Set may arrive as.
///
/// The parameters are ignored — `; charset=utf-8` is common and harmless — and
/// the type is compared case-insensitively, as RFC 9110 §8.3 requires.
#[must_use]
fn is_jwk_set_media_type(header: &str) -> bool {
    let media_type = header
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    JWK_SET_MEDIA_TYPES.contains(&media_type.as_str())
}

#[async_trait::async_trait]
impl JwksFetcher for HttpsJwksFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, DomainError> {
        // One timeout over the whole exchange, resolution included. A per-step
        // timeout would let a server that is slow at every step hold the
        // request for the sum of them.
        let outcome = match tokio::time::timeout(TOTAL_TIMEOUT, self.get(url)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(FetchError::TimedOut {
                host: ssrf::check_url(url).map_or_else(|_| "the URL".to_owned(), |t| t.host),
            }),
        };

        match outcome {
            Ok(body) => Ok(body),
            Err(error) => {
                // The host and the reason, never the URL. A `jwks_uri` is a
                // client-supplied string that may carry a query parameter the
                // client considers a secret, and a log line is not the place to
                // find out.
                tracing::debug!(error = %error, "client JWK Set fetch failed");
                Err(error.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration is built at startup; a failure here would be a
    /// deployment that cannot fetch any client's keys.
    #[test]
    fn the_tls_configuration_builds_and_offers_only_http_1_1() {
        let fetcher = HttpsJwksFetcher::new().expect("build");
        assert_eq!(fetcher.tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// FAPI 2.0 SP §5.2.2 covers server-to-server connections, so the outbound
    /// client offers what the listener offers, not rustls' defaults.
    #[test]
    fn the_outbound_client_uses_the_same_cipher_suites_as_the_listener() {
        let fetcher = HttpsJwksFetcher::new().expect("build");
        let offered: Vec<_> = fetcher
            .tls
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        let expected: Vec<_> = crate::http::tls::CIPHER_SUITES
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        assert_eq!(offered, expected);
    }

    /// A client's key server that serves an HTML error page must not have it
    /// parsed as a JWK Set.
    #[test]
    fn only_json_media_types_are_read_as_a_jwk_set() {
        for accepted in [
            "application/json",
            "application/jwk-set+json",
            "application/json; charset=utf-8",
            "Application/JSON",
            "  application/jwk-set+json  ; charset=UTF-8",
        ] {
            assert!(is_jwk_set_media_type(accepted), "{accepted} was refused");
        }
        for refused in [
            "",
            "text/html",
            "text/plain",
            "application/xml",
            "application/json-patch+json",
            "application/octet-stream",
        ] {
            assert!(!is_jwk_set_media_type(refused), "{refused} was accepted");
        }
    }

    /// A refusal reaches protocol code as a statement about the registration; a
    /// dependency failing reaches it as storage. Neither carries anything a
    /// client could learn from, because the cache above flattens both.
    #[test]
    fn refusals_and_failures_map_onto_different_domain_errors() {
        let refused: DomainError = FetchError::Address {
            host: "client.example".to_owned(),
            address: "127.0.0.1".parse().expect("literal"),
            reason: "loopback",
        }
        .into();
        assert!(matches!(refused, DomainError::Invalid { field, .. } if field == "jwks_uri"));

        let failed: DomainError = FetchError::Connect {
            host: "client.example".to_owned(),
        }
        .into();
        assert!(matches!(failed, DomainError::Storage(_)));
    }

    /// The two halves of `ast-mxc.5` meet at the port, and nothing composes
    /// them yet — `ast-m9c.2` is the first caller. This asserts that they fit:
    /// the fetcher satisfies the port the cache is built on, and an inline
    /// `jwks` resolves through the pair without a socket existing.
    #[tokio::test]
    async fn the_fetcher_satisfies_the_port_the_key_cache_is_built_on() {
        let cache =
            asterius_jose::ClientKeyCache::new(Arc::new(HttpsJwksFetcher::new().expect("build")));
        let key = asterius_jose::SigningKey::generate(asterius_domain::SigningAlgorithm::EdDsa)
            .expect("generate");
        let mut jwk = key.public_jwk().expect("jwk");
        jwk["kid"] = serde_json::json!("k1");

        let resolved = cache
            .resolve(
                &asterius_domain::TenantId::new("demo"),
                &asterius_domain::ClientId::new("client-1"),
                &asterius_domain::JwksSource::Inline(serde_json::json!({"keys": [jwk]})),
                None,
                time::OffsetDateTime::UNIX_EPOCH,
            )
            .await
            .expect("resolve");
        assert_eq!(resolved.verifying_keys().len(), 1);
    }

    /// The guard runs before anything is resolved, so a refused URL never
    /// becomes a packet. Loopback is the case that matters and it is also the
    /// one that needs no network to test.
    #[tokio::test]
    async fn a_loopback_url_is_refused_without_a_connection_being_attempted() {
        let fetcher = HttpsJwksFetcher::new().expect("build");
        for refused in [
            "https://127.0.0.1/jwks",
            "https://[::1]/jwks",
            "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://client.example/jwks",
        ] {
            let error = fetcher.fetch(refused).await.expect_err("must be refused");
            assert!(
                matches!(error, DomainError::Invalid { field, .. } if field == "jwks_uri"),
                "{refused} produced {error}"
            );
        }
    }
}
