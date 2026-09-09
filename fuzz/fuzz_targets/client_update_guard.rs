//! The RFC 7592 §2.2 immutability guard — `update_guard`.
//!
//! Everything a client sends to `PUT /register/{client_id}` reaches this
//! function first, and what it decides is which of the fields in a client's own
//! registration are the client's to set. Getting it wrong in one direction lets
//! a client claim a credential this server does not issue; getting it wrong in
//! the other breaks the read-modify-write round trip §2.2 prescribes. The body
//! is arbitrary bytes from an authenticated but otherwise untrusted party.
//!
//! Five properties, each restated here against the parsed document rather than
//! by asking the code under test:
//!
//! * **A document that passes really does name this client.** §2.2: "The client
//!   MUST include its client_id field in the request, and it MUST be the same
//!   as its currently issued client identifier." Checked byte-for-byte against
//!   the string the URL named — not case-folded, not trimmed, not a prefix.
//! * **A document that passes carries none of the three credential fields.**
//!   `client_secret`, `client_secret_expires_at` and `registration_access_token`
//!   must be absent or explicitly null, the second being what §2.2 allows the
//!   server to treat as absent.
//! * **A document that fails names the field that failed**, from a closed set of
//!   descriptions this server wrote — so an error body can never carry a value
//!   out of the request, which is the reflection primitive an update document
//!   is uniquely able to become (it is where a client puts a secret by
//!   mistake).
//! * **Every description is on the wire grammar.** RFC 6749 Appendix A.8:
//!   `error_description` is `1*NQSCHAR`, `%x20-21 / %x23-5B / %x5D-7E`.
//! * **Deterministic**, and independent of the `client_id` in every way except
//!   equality: the same body judged against the same identifier gives the same
//!   answer, and against a *different* identifier can only fail.
#![no_main]

use asterius_server::http::client_configuration::{NotYours, update_guard};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// Every description the guard can produce, gathered so the target can assert
/// membership rather than absence — the same lesson `initial_access_token`
/// learned, where "does not contain the credential" turned out not to be a leak
/// detector at all.
const DESCRIPTIONS: [&str; 4] = [
    NotYours::ClientId.description(),
    NotYours::ClientSecret.description(),
    NotYours::ClientSecretExpiresAt.description(),
    NotYours::RegistrationAccessToken.description(),
];

/// The three members a passing document must not carry.
const CREDENTIAL_FIELDS: [&str; 3] = [
    "client_secret",
    "client_secret_expires_at",
    "registration_access_token",
];

/// The identifiers the fuzzer judges a document against.
///
/// Fixed rather than drawn, so a corpus entry means the same thing on every run.
/// They cover the shapes that a comparison doing anything other than equality
/// would get wrong: an ordinary minted identifier, one that is its prefix, one
/// that differs only in case, and the empty string.
const IDENTIFIERS: [&str; 4] = [
    "c.9tR0nVQ3kZmY1bXeL-oPuA",
    "c.9tR0nVQ3kZmY1bXeL-oPu",
    "C.9TR0NVQ3KZMY1BXEL-OPUA",
    "",
];

/// RFC 6749 Appendix A.8's `NQSCHAR`.
fn nqschar(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| matches!(b, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fuzz_target!(|input: (&[u8], u8)| {
    let (body, which) = input;
    let client_id = IDENTIFIERS[usize::from(which) % IDENTIFIERS.len()];

    let decision = update_guard(body, client_id);

    // Deterministic: nothing here may depend on allocation or ordering.
    assert_eq!(
        decision,
        update_guard(body, client_id),
        "the guard is not stable"
    );

    // The oracle's own view of the document, parsed independently.
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let object = parsed.as_ref().and_then(Value::as_object);

    match decision {
        Ok(()) => {
            // A body that is not a JSON object passes on purpose: the validator
            // owns that rejection. Nothing more to assert about it.
            let Some(object) = object else {
                return;
            };

            // §2.2: the document names exactly this client, byte for byte.
            assert_eq!(
                object.get("client_id").and_then(Value::as_str),
                Some(client_id),
                "a document passed without naming the client the URL did"
            );

            // §2.2: none of the credential fields was set. An explicit null is
            // absence, which §2.2 permits the server to ignore.
            for field in CREDENTIAL_FIELDS {
                assert!(
                    object.get(field).is_none_or(Value::is_null),
                    "{field} survived the guard"
                );
            }

            // The identifier is compared for equality and nothing else, so the
            // same document judged against any other identifier must fail.
            for other in IDENTIFIERS {
                if other != client_id {
                    assert_eq!(
                        update_guard(body, other),
                        Err(NotYours::ClientId),
                        "a document that named {client_id:?} also passed for {other:?}"
                    );
                }
            }
        }
        Err(failure) => {
            // A refusal names a field, from the closed set this server wrote.
            let description = failure.description();
            assert!(
                DESCRIPTIONS.contains(&description),
                "a refusal produced a description this module did not write: {description:?}"
            );
            // RFC 6749 Appendix A.8, checked here rather than trusted: this
            // string goes into an `error_description`, and one that left the
            // grammar would be a header-injection bug the moment somebody moved
            // it into a `WWW-Authenticate` parameter.
            assert!(nqschar(description), "{description:?} is not 1*NQSCHAR");

            // The refusal is justified by the document itself: either it does
            // not name this client, or it carries a field it may not.
            let names_us = object
                .and_then(|object| object.get("client_id"))
                .and_then(Value::as_str)
                == Some(client_id);
            let claims_a_credential = object.is_some_and(|object| {
                CREDENTIAL_FIELDS
                    .iter()
                    .any(|field| object.get(*field).is_some_and(|value| !value.is_null()))
            });
            assert!(
                !names_us || claims_a_credential,
                "a document that named this client and claimed nothing was still refused"
            );
            if failure == NotYours::ClientId {
                assert!(
                    !names_us,
                    "a document that named this client failed on client_id"
                );
            }
        }
    }
});
