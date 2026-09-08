//! `GrantRecord::validate` and `LiveAccessToken::new` — the two validators a
//! grant row passes through on its way out of the database.
//!
//! A `grants` row is not client input, which is the reason to fuzz it rather
//! than a reason not to. Three of its columns are `jsonb` and two are `text[]`:
//! the database holds whatever is put in them, and what is put in them comes
//! from a seed script, a migration, a support tool, or somebody in a `psql`
//! session at three in the morning. Everything that comes back out is then
//! copied into an access token.
//!
//! So the properties asserted here are the ones nothing downstream re-checks:
//!
//! * **An accepted scope cannot split.** The scopes of a grant are joined with
//!   spaces into the `scope` claim (RFC 9068 §2.2.3) and the `scope` member of
//!   a token response (RFC 6749 §5.1). Splitting that string again must return
//!   exactly the scopes that went in — one stored scope containing a space
//!   would otherwise *become two scopes* at the resource server.
//! * **An accepted resource is an audience something can match.** RFC 8707 §2:
//!   absolute, no fragment. A resource that is neither is an `aud` no resource
//!   server ever compares equal to.
//! * **A revoked row is never mistaken for a live one.** `revoked_at` and
//!   `revocation_reason` are accepted only together, and an accepted revoked
//!   grant reports `revoked` at every instant and refuses every claim — which
//!   is `revoked -> active`, the transition that must not exist.
//! * **A claim is possible exactly when the status says so.** No third answer,
//!   at any timestamp.
//! * **An accepted `jti` can be stored.** It becomes half of a primary key in a
//!   `text` column; a byte PostgreSQL refuses would abort the transaction
//!   carrying a revocation, which is a revocation that silently did not happen.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::{
    ClientId, Grant, GrantId, GrantRecord, GrantStatus, LiveAccessToken, RevocationReason, TenantId,
};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

/// The JSON shapes a `jsonb` column can hold, near-misses first. Random bytes
/// are almost never JSON, and never the two shapes a rule has to tell apart.
const SHAPES: [&str; 8] = [
    "{}",
    "[]",
    "null",
    "0",
    "\"a string\"",
    "{\"type\":\"payment_initiation\"}",
    "[{\"type\":\"payment_initiation\"}]",
    "[[]]",
];

/// Scope and resource candidates, half of them the ones that must be refused,
/// spelled the ways somebody would type them.
const TOKENS: [&str; 12] = [
    "openid",
    "payments accounts",
    "pay\"ments",
    "pay\\ments",
    "",
    "urn:example:scope",
    "https://api.example/",
    "https://api.example/#frag",
    "/api",
    "api.example",
    "mailto:a@example.com",
    "https://api.example/v1?x=1",
];

#[derive(Arbitrary, Debug)]
struct Input {
    scope_picks: Vec<u8>,
    scope_free: String,
    resource_picks: Vec<u8>,
    resource_free: String,
    claims: u8,
    authorization_details: u8,
    actor_chain: u8,
    reason: Option<String>,
    revoked: bool,
    expires_after: Option<i32>,
    claimed_after: Option<i32>,
    parented: bool,
    subject: Option<String>,
    jti: String,
    at: i32,
}

fn json(pick: u8) -> serde_json::Value {
    serde_json::from_str(SHAPES[usize::from(pick) % SHAPES.len()]).expect("a fixed shape parses")
}

fn strings(picks: &[u8], free: &str) -> Vec<String> {
    let mut out: Vec<String> = picks
        .iter()
        .take(80)
        .map(|pick| TOKENS[usize::from(*pick) % TOKENS.len()].to_owned())
        .collect();
    out.push(free.to_owned());
    out
}

fn instant(seconds: i32) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(i64::from(seconds))
}

fuzz_target!(|input: Input| {
    let tenant = TenantId::new("demo");
    let created_at = OffsetDateTime::UNIX_EPOCH;
    let record = GrantRecord {
        id: GrantId::new("2c1d4b1e-0000-4000-8000-000000000001"),
        client: ClientId::new("billing"),
        user: None,
        subject: input.subject.clone(),
        scopes: strings(&input.scope_picks, &input.scope_free),
        claims: json(input.claims),
        authorization_details: json(input.authorization_details),
        resources: strings(&input.resource_picks, &input.resource_free),
        actor_chain: json(input.actor_chain),
        parent: input
            .parented
            .then(|| GrantId::new("2c1d4b1e-0000-4000-8000-000000000002")),
        session: None,
        created_at,
        updated_at: created_at,
        expires_at: input.expires_after.map(instant),
        claimed_at: input.claimed_after.map(instant),
        revoked_at: input.revoked.then_some(created_at),
        revocation_reason: input.reason.clone(),
    };

    // Validation is a pure function of the row: the read path is taken by
    // several callers and they cannot be allowed to disagree.
    let first = record.clone().validate(&tenant);
    assert_eq!(
        first.is_ok(),
        record.clone().validate(&tenant).is_ok(),
        "validating a grant row is not deterministic"
    );

    // The `jti` half, which has nothing to do with the row but everything to do
    // with the revocation that reads it.
    match LiveAccessToken::new(input.jti.clone(), created_at) {
        Ok(token) => {
            assert_eq!(token.jti(), input.jti, "a jti was rewritten on the way in");
            assert!(!token.jti().is_empty(), "an unmatchable denylist row");
            assert!(
                token
                    .jti()
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b' '),
                "a jti PostgreSQL may refuse reached the denylist: {:?}",
                token.jti()
            );
            assert!(token.jti().len() <= Grant::MAX_JTI_LEN);
        }
        Err(_) => assert!(
            input.jti.is_empty()
                || input.jti.len() > Grant::MAX_JTI_LEN
                || !input.jti.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
            "a storable jti was refused: {:?}",
            input.jti
        ),
    }

    let Ok(grant) = first else { return };

    // --- scopes survive the round trip through a space-delimited claim ------

    let joined = grant
        .scopes
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let split: Vec<&str> = if joined.is_empty() {
        Vec::new()
    } else {
        joined.split(' ').collect()
    };
    assert_eq!(
        split.len(),
        grant.scopes.len(),
        "a stored scope split into two on the way into a token: {joined:?}"
    );
    for scope in &grant.scopes {
        assert!(!scope.is_empty());
        assert!(scope.len() <= Grant::MAX_SCOPE_LEN);
        assert!(
            !scope
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\\'),
            "a scope kept a character RFC 6749 §3.3 does not allow: {scope:?}"
        );
    }
    assert!(grant.scopes.len() <= Grant::MAX_SCOPES);

    // --- resources are audiences something can match ------------------------

    assert!(grant.resources.len() <= Grant::MAX_RESOURCES);
    for resource in &grant.resources {
        let parsed = url::Url::parse(resource).expect("an accepted resource is a URL");
        assert!(
            parsed.fragment().is_none(),
            "a resource with a fragment became an aud: {resource:?}"
        );
        assert!(!parsed.cannot_be_a_base());
    }

    // --- the shapes the JSON columns are copied into a token as -------------

    assert!(grant.claims.is_object(), "claims must be an object");

    // --- the lifecycle ------------------------------------------------------

    let revoked = grant.revoked_at.is_some();
    assert_eq!(
        revoked,
        grant.revocation_reason.is_some(),
        "a half-written revocation loaded"
    );
    if let Some(reason) = grant.revocation_reason {
        assert!(RevocationReason::ALL.contains(&reason));
    }

    for at in [i32::MIN, -1, 0, 1, input.at, i32::MAX] {
        let now = instant(at);
        let status = grant.status(now);

        // `revoked` outranks everything, at every instant.
        assert_eq!(
            revoked,
            status == GrantStatus::Revoked,
            "a revoked grant reported {status} at {now}"
        );

        // A claim is possible exactly when the status says so — and never for a
        // revoked grant, which is `revoked -> active` refused.
        assert_eq!(
            grant.claim(now).is_ok(),
            status.may_issue(),
            "the claim guard and the status disagree at {now}"
        );
        assert!(
            !revoked || grant.claim(now).is_err(),
            "a revoked grant issued a credential at {now}"
        );

        // And the status is one the lifecycle can reach from where the grant
        // started: nothing derives a state that is not a successor of pending.
        assert!(
            status == GrantStatus::Pending || GrantStatus::Pending.may_become(status),
            "a grant derived the unreachable status {status}"
        );
    }
});
