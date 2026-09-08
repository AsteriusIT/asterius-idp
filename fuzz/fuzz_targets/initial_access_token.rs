//! The dynamic client registration gate — RFC 7591 §3, RFC 6750 §2.1.
//!
//! `RegistrationPolicy::admit` is the whole authorization decision for
//! `POST /register`, and it is the only thing standing between the internet and
//! a row in `clients`. Its input is an `Authorization` header, which is the
//! rawest attacker-controlled bytes this server reads: a header value can hold
//! anything the HTTP layer will carry, including a token that differs from a
//! configured one by a space, a case, an encoding or an invisible character.
//!
//! The properties asserted are the ones the endpoint trusts without re-checking:
//!
//! * **A closed policy admits nothing.** Whatever the header says. This is the
//!   default, so it is the one that must have no exception at all.
//! * **An open policy admits everything**, including a request with no header —
//!   because that is what "open" means, and a subtle refusal would be a policy
//!   nobody chose.
//! * **A gated policy admits exactly the configured tokens.** Restated here
//!   against the presented bytes rather than by asking the code under test:
//!   an admitted request must have carried `Bearer ` followed by a byte string
//!   equal to one of the tokens this deployment was given.
//! * **The scheme is matched case-insensitively and nothing else is**
//!   (RFC 9110 §11.1) — an admitted request's credential is byte-identical to a
//!   configured token, never a case-folded, trimmed or normalised version of
//!   one.
//! * **A denial is total.** Every refusal path returns a `Denial` whose code is
//!   from the closed set the endpoint renders, and the two 401 cases carry a
//!   `WWW-Authenticate` challenge (RFC 6750 §3 makes it mandatory).
//! * **Deterministic.** The same header twice gives the same answer, so no
//!   admission depends on allocation, ordering or timing.
#![no_main]

use arbitrary::Arbitrary;
use asterius_server::http::register::{Denial, InitialAccessTokens, RegistrationPolicy};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use libfuzzer_sys::fuzz_target;

/// The tokens the fuzzed deployment was configured with.
///
/// Fixed rather than drawn, so that a corpus entry means the same thing on
/// every run and a crash reproduces. They cover the shapes a real deployment
/// has: an ordinary `base64url` draw, one with both of the alphabet's
/// punctuation characters, and one whose prefix is another one's whole value —
/// the case a comparison that stopped early would get wrong.
const CONFIGURED: [&str; 3] = [
    "vJ8qN2mXbL5-tRw0KePzUA",
    "0PIVxTz6ThDcJdxCoWnk8w_-",
    "vJ8qN2mXbL5-tRw0KePzUAxx",
];

/// Every description a refusal may carry, gathered so the target can assert
/// membership rather than absence.
const DESCRIPTIONS: [&str; 3] = [
    Denial::Closed.description(),
    Denial::Missing.description(),
    Denial::Invalid.description(),
];

/// How the fuzzer spells the `Authorization` header.
#[derive(Arbitrary, Debug)]
enum Credential {
    /// No header at all.
    Absent,
    /// `Bearer ` followed by one of the configured tokens, verbatim.
    Configured(u8),
    /// `Bearer ` followed by arbitrary text.
    Bearer(String),
    /// An arbitrary scheme name followed by a configured token — the case where
    /// only the scheme is wrong.
    Scheme(String, u8),
    /// Whatever the fuzzer likes.
    Raw(String),
}

impl Credential {
    fn header(&self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Configured(which) => Some(format!("Bearer {}", pick(*which))),
            Self::Bearer(text) => Some(format!("Bearer {text}")),
            Self::Scheme(scheme, which) => Some(format!("{scheme} {}", pick(*which))),
            Self::Raw(text) => Some(text.clone()),
        }
    }
}

fn pick(which: u8) -> &'static str {
    CONFIGURED[usize::from(which) % CONFIGURED.len()]
}

/// Whether `HeaderValue::to_str` would hand this value back, which is the test
/// for visible ASCII: every byte in `%x20-7E`.
fn readable(header: &str) -> bool {
    header.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// The bytes after the first space, which is what RFC 6750 §2.1 calls the
/// credential. Recomputed here so the oracle and the code under test do not
/// share a parser.
fn presented(header: &str) -> Option<&str> {
    let (scheme, credential) = header.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(credential)
}

#[derive(Arbitrary, Debug)]
struct Input {
    credential: Credential,
    /// Whether the header is sent twice with different values, which is how a
    /// proxy or a confused client produces two `Authorization` lines.
    duplicate: Option<String>,
}

fuzz_target!(|input: Input| {
    let rendered = input.credential.header();
    let mut headers = HeaderMap::new();
    if let Some(value) = &rendered {
        // A header value that cannot be constructed is one no HTTP layer would
        // ever deliver, so there is nothing to test in that case.
        let Ok(value) = HeaderValue::try_from(value.as_str()) else {
            return;
        };
        headers.insert(header::AUTHORIZATION, value);
    }
    if let Some(extra) = &input.duplicate
        && let Ok(value) = HeaderValue::try_from(extra.as_str())
    {
        headers.append(header::AUTHORIZATION, value);
    }

    let gated = RegistrationPolicy::Gated(InitialAccessTokens::from_tokens(CONFIGURED));

    // --- a closed deployment admits nothing, whatever the header says ---
    assert_eq!(
        RegistrationPolicy::Closed.admit(&headers),
        Err(Denial::Closed),
        "a closed deployment admitted a caller"
    );

    // --- an open deployment admits everything, including no header at all ---
    assert_eq!(
        RegistrationPolicy::Open.admit(&headers),
        Ok(()),
        "an open deployment refused a caller"
    );

    let decision = gated.admit(&headers);

    // Deterministic: the same headers must give the same answer twice.
    assert_eq!(decision, gated.admit(&headers), "admission is not stable");

    match decision {
        Ok(()) => {
            // An admitted request carried a bearer credential that is
            // byte-for-byte one of the configured tokens. Checked against the
            // header the fuzzer built, not against anything the code returned.
            let header = rendered.as_deref().expect("admitted a request with no header");
            let credential = presented(header)
                .expect("admitted a request whose scheme is not Bearer");
            assert!(
                CONFIGURED.contains(&credential),
                "admitted a credential that was never configured: {credential:?}"
            );
            // Nothing was trimmed, folded or normalised on the way in: an
            // accepted credential is the configured token exactly, so a token
            // issued in one spelling cannot be spent in another.
            assert!(
                CONFIGURED.iter().any(|known| known.as_bytes() == credential.as_bytes()),
                "an admitted credential is not byte-identical to a configured one"
            );
        }
        Err(denial) => {
            // A refusal is one of three, and each one has to be answerable.
            assert!(
                matches!(denial, Denial::Missing | Denial::Invalid),
                "a gated policy produced {denial:?}"
            );
            assert_eq!(denial.status(), StatusCode::UNAUTHORIZED);
            // RFC 6750 §3: both 401 cases carry a challenge.
            assert!(
                denial.challenge().is_some(),
                "a 401 without WWW-Authenticate"
            );
            assert_eq!(denial.code(), "invalid_token");

            // The description is one of three compile-time constants, so it
            // cannot carry anything out of the request.
            //
            // Asserted as membership rather than as "does not contain the
            // credential", which is what this was first written as. That check
            // is not a leak detector: a one-character credential is a substring
            // of any English sentence, and so is a longer run that happens to
            // spell "l access". The fuzzer found the first case within a minute.
            // Byte-equality with a constant is the property that actually
            // matters and the only one with no false positives.
            let description = denial.description();
            assert!(
                DESCRIPTIONS.contains(&description),
                "a refusal produced a description this module did not write: {description:?}"
            );
            assert!(description.is_ascii() && !description.is_empty());

            // The refusal that a *presented* credential gets must not be the
            // one that means "you sent nothing", or a client with a revoked
            // token would be told to send the one it just sent.
            //
            // `readable` is not incidental. `HeaderValue` accepts obs-text
            // (0x80-0xFF), so `Bearer é` is a header a client really can send,
            // and `HeaderValue::to_str` refuses it because it is not visible
            // ASCII. RFC 6750 §2.1's `b64token` is ASCII, so such a value is not
            // a bearer credential at all and the endpoint answers `Missing`
            // rather than `Invalid` — the same answer `Basic …` gets. The
            // fuzzer found this by treating a Rust `String` as though the HTTP
            // layer would hand it back unchanged, which it does not.
            if let Some(header) = &rendered
                && readable(header)
                && let Some(credential) = presented(header)
                && !CONFIGURED.contains(&credential)
            {
                assert_eq!(denial, Denial::Invalid);
            }
        }
    }
});
