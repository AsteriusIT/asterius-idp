//! `revocation::classify` — the parser standing in front of the endpoint that
//! withdraws credentials.
//!
//! A revocation request is reachable by any registered client, its `token`
//! parameter is a string somebody else composed, and what this function
//! returns decides which of two writes happens: a stamped refresh-token row,
//! or a denylist row keyed by a `jti`. Three properties are worth a fuzzer
//! rather than a unit test:
//!
//! * **It never panics.** The base64 decode and the JSON parse both happen on
//!   an unverified header; a panic here is a 500 an attacker composes.
//! * **`RefreshToken` means the shape of a refresh token, and its digest is a
//!   lookup key.** Sixty-four hex characters, never the value itself. This is
//!   the one branch that turns an attacker-supplied string into a database
//!   query, and it must agree with `refresh::digest_of` exactly — a drift
//!   there is either a token that cannot be revoked or a query on a value that
//!   was never a token.
//! * **Only `at+jwt` classifies as an access token.** That branch leads to a
//!   `jti` being read from the token and written as a primary key, and the
//!   `typ` is the check that stops an ID token, a logout token or a client
//!   assertion getting that far.
#![no_main]

use asterius_oidc::refresh::{MintedRefreshToken, REFRESH_TOKEN_LEN, digest_of};
use asterius_oidc::revocation::{MAX_TOKEN_LEN, Presented, classify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|token: String| {
    match classify(&token) {
        Ok(Presented::RefreshToken { digest }) => {
            assert_eq!(digest.len(), 64, "not a SHA-256 digest: {digest:?}");
            assert!(
                digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "a digest outside hex: {digest:?}"
            );
            assert_ne!(digest, token, "the digest is the value it digested");
            // The two must be the same function, or a token is revoked under a
            // key nothing was filed under.
            assert_eq!(
                Ok(digest),
                digest_of(&token),
                "classification and lookup disagree"
            );
            assert_eq!(
                token.len(),
                REFRESH_TOKEN_LEN,
                "a value of the wrong length was taken for a refresh token"
            );
        }
        Ok(Presented::AccessToken) => {
            // The branch that reads a `jti` out of the token. Getting here on
            // anything but a three-segment JWT typed `at+jwt` would mean the
            // type check is not the gate it is documented to be.
            assert_eq!(
                token.split('.').count(),
                3,
                "a non-JWT was taken for an access token: {token:?}"
            );
            assert!(
                token.len() <= MAX_TOKEN_LEN,
                "a value past the bound was classified"
            );
        }
        // §2.1's invalid token, and §2.2.1's refusal. Both are answers, not
        // states this function may be in.
        Ok(Presented::Unrecognised) | Err(_) => {}
    }

    // Whatever else it does, it agrees with the minter: a token this server
    // has just issued is one this endpoint can revoke.
    let minted = MintedRefreshToken::generate();
    assert_eq!(
        classify(minted.expose()),
        Ok(Presented::RefreshToken {
            digest: minted.digest().to_owned()
        }),
        "a freshly minted refresh token is not revocable"
    );
});
