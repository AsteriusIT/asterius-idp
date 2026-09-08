//! `code::digest_of` and `AuthorizationResponse::redirect_url` — the two
//! places an authorization response is built from values somebody else chose.
//!
//! `digest_of` is a shape check standing in front of a database query, so what
//! matters is that it agrees with the minter: any value `MintedCode` produces
//! must pass, anything it accepts must digest to something a lookup can use,
//! and it must never panic on a byte sequence a client can put in a form field.
//!
//! `redirect_url` is the interesting one. It builds the URL a browser is
//! redirected to out of a registered `redirect_uri`, an echoed `state` and a
//! code, and every one of those is attacker-influenced from some direction:
//!
//! * **A `state` cannot add a parameter.** It is echoed byte-for-byte (RFC 6749
//!   §4.1.2), so a `state` of `x&code=stolen` must arrive at the client as one
//!   `state` and not as a second `code`. A client reading the first `code` it
//!   finds would otherwise redeem the attacker's.
//! * **`iss` is on every response.** RFC 9207 §2, and on the error path too —
//!   the mix-up attack works just as well with an error, and a client that only
//!   checks `iss` on success can still be steered.
//! * **A response never carries both a `code` and an `error`.** OIDC Core
//!   §3.1.2.5 and §3.1.2.6 are two responses, and a client presented with both
//!   gets to choose which one it is.
//! * **The redirect stays on the registered URI.** Same scheme, host, port and
//!   path as the stored value: parameters are appended, never a new location.
//! * **Nothing lands in the fragment.** A parameter that ended up after a `#`
//!   would never reach the client's server at all.
#![no_main]

use arbitrary::Arbitrary;
use asterius_oidc::code::{AuthorizationResponse, MalformedCode, MintedCode, digest_of};
use libfuzzer_sys::fuzz_target;

/// Registered redirect URIs, spelled the ways a registration document can hold
/// them — including the ones that already carry a query, which RFC 6749 §3.1.2
/// permits and whose parameters the client gets to keep.
const REDIRECTS: [&str; 10] = [
    "https://rp.example/cb",
    "https://rp.example/cb?tenant=x",
    "https://rp.example/cb?code=already",
    "https://rp.example/",
    "https://rp.example/cb#fragment",
    "https://rp.example:8443/cb",
    "com.example.app:/oauth2redirect",
    "http://127.0.0.1:1234/cb",
    "not a url",
    "",
];

/// The `error` codes RFC 6749 §4.1.2.1 defines, plus the one this server sends
/// when it cannot finish what a user already agreed to.
const ERRORS: [&str; 5] = [
    "access_denied",
    "server_error",
    "temporarily_unavailable",
    "invalid_request",
    "unauthorized_client",
];

#[derive(Arbitrary, Debug)]
struct Input {
    presented: String,
    redirect: u8,
    error: u8,
    state: Option<String>,
    code: String,
    issuer: String,
    is_error: bool,
}

fn pick<'a>(table: &[&'a str], index: u8) -> &'a str {
    table[usize::from(index) % table.len()]
}

fuzz_target!(|input: Input| {
    // --- digest_of ---------------------------------------------------------

    match digest_of(&input.presented) {
        Ok(digest) => {
            // What is handed to the store must be a lookup key, not a value
            // that will be spliced into anything.
            assert_eq!(digest.len(), 64, "not a SHA-256 digest: {digest:?}");
            assert!(
                digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "a digest outside hex: {digest:?}"
            );
            assert_eq!(
                digest,
                digest_of(&input.presented).expect("accepted once, accepted twice"),
                "digesting is not deterministic"
            );
        }
        Err(MalformedCode) => {}
    }

    // A minted code always passes its own check, and digests to what the
    // minter stored. A drift between these two is a server that can never
    // redeem anything it issues.
    let minted = MintedCode::generate();
    assert_eq!(
        digest_of(minted.expose()).expect("a minted code must be accepted"),
        minted.digest()
    );
    // ...and the value itself is never the stored form.
    assert_ne!(minted.expose(), minted.digest());

    // --- redirect_url ------------------------------------------------------

    let redirect = pick(&REDIRECTS, input.redirect);
    let response = if input.is_error {
        AuthorizationResponse::Error {
            error: pick(&ERRORS, input.error),
            state: input.state.clone(),
            issuer: input.issuer.clone(),
        }
    } else {
        AuthorizationResponse::Code {
            code: input.code.clone(),
            state: input.state.clone(),
            issuer: input.issuer.clone(),
        }
    };

    // RFC 9207 §2: on both variants, before anything is rendered.
    let pairs = response.query();
    assert!(
        pairs.iter().any(|(name, _)| *name == "iss"),
        "an authorization response with no iss: {pairs:?}"
    );

    let Ok(url) = response.redirect_url(redirect) else {
        // A registered URI that will not parse is refused rather than guessed
        // at. Only the values `Url` cannot read may take this path.
        assert!(
            url::Url::parse(redirect).is_err(),
            "a parseable redirect URI was refused: {redirect:?}"
        );
        return;
    };

    let built = url::Url::parse(&url).expect("what we built must parse");
    let registered = url::Url::parse(redirect).expect("it parsed a moment ago");

    // The location is the registered one. Only the query may differ.
    assert_eq!(built.scheme(), registered.scheme());
    assert_eq!(built.host_str(), registered.host_str());
    assert_eq!(built.port(), registered.port());
    assert_eq!(built.path(), registered.path());
    assert_eq!(
        built.fragment(),
        registered.fragment(),
        "a parameter reached the fragment, where a client's server never sees it"
    );

    let values = |name: &str| -> Vec<String> {
        built
            .query_pairs()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .collect()
    };

    // One response, not two. A client handed both gets to choose which.
    let codes = values("code");
    let errors = values("error");
    assert!(
        codes.is_empty() || errors.is_empty(),
        "a response carried both a code and an error: {url}"
    );

    if input.is_error {
        assert_eq!(errors, vec![pick(&ERRORS, input.error)], "{url}");
        assert!(codes.is_empty(), "an error response carried a code: {url}");
    } else {
        // Exactly one, whatever the registration held. A registered
        // `?code=already` is the case where a client reading the *first*
        // `code` would redeem somebody else's, so the response must not leave
        // two for it to choose between.
        assert_eq!(
            codes,
            vec![input.code.clone()],
            "an approval did not produce exactly one code: {url}"
        );
    }

    // `state` is echoed byte-for-byte, or absent. A registered one is dropped
    // rather than kept: a `state` the client set in its own registration would
    // defeat the CSRF check `state` exists to make.
    assert_eq!(
        values("state"),
        input.state.clone().map(|s| vec![s]).unwrap_or_default(),
        "the state was altered, invented or duplicated: {url}"
    );

    // One issuer, unaltered — a client compares it against a string it holds.
    assert_eq!(values("iss"), vec![input.issuer.clone()], "{url}");

    // And nothing the registration held under one of those names survived.
    for (name, _) in registered.query_pairs() {
        if asterius_oidc::code::RESERVED.contains(&name.as_ref()) {
            continue;
        }
        assert!(
            built.query_pairs().any(|(k, _)| k == name),
            "a registered parameter was dropped: {name} in {url}"
        );
    }
});
