//! The claim bag the console's account screen writes, and the account body
//! beside it.
//!
//! This is the validator standing between an administrator's browser and the
//! **claims a relying party is told about a person**. It is reached only with
//! a session and a synchroniser token, but "authenticated" is not "trusted":
//! an administrator whose browser is running somebody else's script is exactly
//! the caller this parser exists for, and the values it accepts are handed to
//! every client that asks for them afterwards.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes are a request body. Parsing one must not
//!   panic.
//! * **The bag cannot hold a `sub`.** OIDC Core §2 makes `sub` the identifier
//!   a relying party keys its account on, and `iss`, `aud`, `acr`, `amr`,
//!   `nonce`, `auth_time` and the rest are minted by the authorization server
//!   about a *transaction*. A bag able to hold one of them is a bag able to
//!   impersonate somebody, so whatever an operator types, none of those names
//!   may come out of the parser.
//! * **A claim that lives in a column does not also live in the bag.** `email`,
//!   `email_verified` and `updated_at` are columns on the account; a claim of
//!   the same name would be a second answer to the same question, and the two
//!   would disagree the moment one was edited.
//! * **Nothing is unbounded.** The body arrives from the network and every
//!   accepted claim is read on the `userinfo` path afterwards, so the count and
//!   each value's serialised size are capped.
//! * **A verification time is the server's.** OIDC Core §5.1 makes
//!   `email_verified` a statement the *provider* makes; a caller may assert
//!   that a claim is checked but must never choose the instant, so every
//!   accepted `verified_at` is exactly the `now` the handler passed.
//! * **A `null` value is refused.** §5.3.2 says an unavailable claim is
//!   omitted rather than returned empty, so a stored `null` would be a claim
//!   that exists and asserts nothing — which a relying party is entitled to
//!   read as "the provider asserts no value".
//! * **A flag is never asserted about an address that is not there.**
#![no_main]

use asterius_admin_api::users::{
    MAX_CLAIM_VALUE_BYTES, MAX_CLAIMS, RequestedAccount, RequestedClaims, accept_account,
    accept_claims, apply_claims,
};
use asterius_domain::{ClaimSet, ClaimSource, TenantId, User, UserId, UserStatus};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

/// The names the authorization server mints for itself, and the ones that live
/// in a column. Neither may ever appear in the bag.
const RESERVED: [&str; 12] = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "nonce",
    "acr",
    "amr",
    "azp",
    "auth_time",
    "email",
    "email_verified",
];

/// A fixed instant, so that "the server stamped it" is checkable.
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
}

fn tenant() -> TenantId {
    TenantId::parse("fuzz").expect("a valid tenant id")
}

/// The account an edit is applied to.
fn held() -> User {
    User {
        tenant: tenant(),
        id: UserId::generate(),
        username: "held@example.test".to_owned(),
        email: Some("held@example.test".to_owned()),
        email_verified: true,
        status: UserStatus::Active,
        claims: ClaimSet::new(),
        created_at: now(),
        updated_at: now(),
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    // 1. The claim bag, as the whole body and as one claim's name and value.
    //    Dressed as well as raw, so the budget goes on the rules rather than
    //    on failing to be JSON at all.
    let candidates = [
        raw.to_owned(),
        format!(r#"{{{}: {{"value": "x"}}}}"#, serde_json::json!(raw)),
        format!(r#"{{"name": {{"value": {}}}}}"#, serde_json::json!(raw)),
        format!(
            r#"{{"name": {{"value": {}, "verified": true}}}}"#,
            serde_json::json!(raw)
        ),
        // A reserved name beside a legitimate one: the parser must refuse the
        // whole document rather than quietly dropping the dangerous member.
        format!(r#"{{"sub": {{"value": {}}}}}"#, serde_json::json!(raw)),
    ];

    for candidate in &candidates {
        let Ok(members) =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(candidate)
        else {
            continue;
        };
        let Ok(claims) = accept_claims(&members, now()) else {
            continue;
        };

        assert!(
            claims.len() <= MAX_CLAIMS,
            "{} claims were accepted",
            claims.len()
        );
        for (name, claim) in claims.iter() {
            assert!(
                !RESERVED.contains(&name.base()),
                "{candidate:?} put {name} in the claim bag"
            );
            assert!(
                !claim.value().is_null(),
                "a null claim value survived: {name}"
            );
            let encoded = serde_json::to_string(claim.value()).expect("a serialisable value");
            assert!(
                encoded.len() <= MAX_CLAIM_VALUE_BYTES,
                "a {} byte claim value was accepted",
                encoded.len()
            );
            assert_eq!(
                claim.source(),
                &ClaimSource::Admin,
                "a claim written through the console claims another source"
            );
            if let Some(at) = claim.verified_at() {
                assert_eq!(at, now(), "a caller chose when a claim was verified");
            }
        }
    }

    // 2. The creation body, whole and dressed as a username.
    for candidate in [
        raw.to_owned(),
        format!(r#"{{"username": {}}}"#, serde_json::json!(raw)),
        format!(
            r#"{{"username": "a", "email": {}, "email_verified": true}}"#,
            serde_json::json!(raw)
        ),
        format!(
            r#"{{"username": "a", "password": {}}}"#,
            serde_json::json!(raw)
        ),
        format!(
            r#"{{"username": "a", "claims": {{"sub": {{"value": {}}}}}}}"#,
            serde_json::json!(raw)
        ),
    ] {
        let Ok(requested) = serde_json::from_str::<RequestedAccount>(&candidate) else {
            continue;
        };
        let Ok(account) = accept_account(&requested, &tenant(), now()) else {
            continue;
        };
        assert!(
            !account.user.username.is_empty(),
            "an empty username was accepted"
        );
        assert!(
            !account.user.username.chars().any(char::is_control),
            "a control character survived into a username"
        );
        assert!(
            !account.user.email_verified || account.user.email.is_some(),
            "email_verified was asserted about an address that is not there"
        );
        for (name, _) in account.user.claims.iter() {
            assert!(
                !RESERVED.contains(&name.base()),
                "{candidate:?} created an account carrying {name} in its bag"
            );
        }
    }

    // 3. The claims-replacement body, which carries the address, its flag and
    //    the whole bag — one document, because an address and a flag that
    //    could be saved separately are an address that can be marked verified
    //    after it was changed.
    for candidate in [
        raw.to_owned(),
        format!(
            r#"{{"email": {}, "email_verified": true, "claims": {{}}}}"#,
            serde_json::json!(raw)
        ),
        format!(
            r#"{{"email": "a@b.test", "claims": {{{}: {{"value": "x"}}}}}}"#,
            serde_json::json!(raw)
        ),
    ] {
        let Ok(requested) = serde_json::from_str::<RequestedClaims>(&candidate) else {
            continue;
        };
        let Ok(edited) = apply_claims(&held(), &requested, now()) else {
            continue;
        };
        assert!(
            !edited.email_verified || edited.email.is_some(),
            "email_verified survived an edit that left no address"
        );
        for (name, claim) in edited.claims.iter() {
            assert!(
                !RESERVED.contains(&name.base()),
                "{candidate:?} put {name} in the claim bag"
            );
            assert!(!claim.value().is_null(), "a null claim value survived");
        }
    }
});
