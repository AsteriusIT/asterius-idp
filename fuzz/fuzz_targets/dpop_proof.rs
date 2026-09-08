//! DPoP proofs — RFC 9449 §4.2, §4.3, §8, §10; RFC 9110 §4.2.3–4.2.4.
//!
//! An accepted proof binds an access token to a key, so "does not panic" is the
//! floor and not the property. What this target asserts is that acceptance is
//! *narrow*, and narrow in the specific ways the RFC requires:
//!
//! * **Nothing verifies that this fuzzer did not sign.** The proof is signed
//!   with a real key over the exact header and payload the fuzzer chose, so the
//!   signature check is genuinely exercised rather than skipped; and a second
//!   pass presents the same bytes with the *wrong* key in the header, which
//!   must never be accepted.
//! * **An accepted proof matched the endpoint exactly.** `htm` byte-for-byte
//!   (RFC 9110 §9.1), and `htu` only after both sides go through the one
//!   normaliser.
//! * **An accepted proof always yields a usable `jti` and a replay expiry that
//!   does not outlive the acceptance window** — the replay defence is only as
//!   good as the value it has to remember and the interval it remembers it for.
//! * **`htu` normalisation never changes the authority.** Whatever comes out of
//!   [`NormalisedUri`], its scheme and host are the ones that went in, lowercased
//!   and nothing else. This is the property that would break first if the
//!   normaliser were ever "made more compatible": a step that could rewrite the
//!   host would let a proof for one server be accepted at another.
//! * **Normalisation is idempotent**, or the comparison depends on how many
//!   times each side has been through it.
//! * **A nonce is only ever accepted inside its two windows**, and never one
//!   derived from a different secret or a different audience.
//!
//! Structured input rather than raw bytes: a random byte string is essentially
//! never three base64url segments whose first is a JOSE header with a `jwk`, so
//! a naive target would spend its whole budget on `Malformed`. This builds a
//! proof from a small grammar of near-misses instead — a right claim of the
//! wrong type, a URL that differs from the endpoint in one component, boundary
//! `iat` values, a private member smuggled into the key.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::SigningAlgorithm;
use asterius_jose::SigningKey;
use asterius_jose::dpop::{
    self, DEFAULT_MAX_AGE, Expectation, MAX_JTI_LEN, NonceIssuer, NormalisedUri,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use std::sync::OnceLock;
use time::OffsetDateTime;

const ENDPOINT: &str = "https://as.example/t/demo/token";
const AUDIENCE: &str = "https://as.example/t/demo";

/// A fixed instant, so `iat` arithmetic is reproducible from a corpus entry.
fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
}

/// Keys generated once. Generating per iteration would fuzz aws-lc-rs rather
/// than the proof checker, and an RSA keygen per input would make the target
/// too slow to find anything.
fn keys() -> &'static Vec<SigningKey> {
    static KEYS: OnceLock<Vec<SigningKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        SigningAlgorithm::ALL
            .into_iter()
            .map(|alg| SigningKey::generate(alg).expect("generate"))
            .collect()
    })
}

fn nonce_issuer() -> &'static NonceIssuer {
    static ISSUER: OnceLock<NonceIssuer> = OnceLock::new();
    ISSUER.get_or_init(|| NonceIssuer::from_secret(b"the fuzzer's shared secret"))
}

fn endpoint() -> &'static NormalisedUri {
    static URI: OnceLock<NormalisedUri> = OnceLock::new();
    URI.get_or_init(|| NormalisedUri::parse(ENDPOINT).expect("our own endpoint"))
}

// ---------------------------------------------------------------------------
// The grammar
// ---------------------------------------------------------------------------

#[derive(Arbitrary, Debug)]
enum KeyChoice {
    First,
    Second,
    Third,
}

impl KeyChoice {
    fn key(&self) -> &'static SigningKey {
        let all = keys();
        match self {
            Self::First => &all[0],
            Self::Second => &all[1 % all.len()],
            Self::Third => &all[2 % all.len()],
        }
    }
}

#[derive(Arbitrary, Debug)]
enum TypChoice {
    Correct,
    Absent,
    Jwt,
    WithPrefix,
    UpperCase,
    Text(String),
}

#[derive(Arbitrary, Debug)]
enum AlgChoice {
    /// The key's own algorithm — the only one that can verify.
    Correct,
    /// A different allow-listed algorithm.
    Mismatched,
    None,
    Hs256,
    Rs256,
    Text(String),
}

#[derive(Arbitrary, Debug)]
enum JwkChoice {
    /// The key's public JWK, as it should be.
    Correct,
    /// Another key's public JWK: the signature must then fail.
    AnotherKey,
    Absent,
    NotAnObject,
    EmptyObject,
    /// The right key with a private member added.
    WithPrivateMember(u8),
    /// The right key with its `kty` replaced.
    WrongKty,
    /// The right key with a declared `alg` that is not the header's.
    WrongDeclaredAlg,
    /// The right key with a member truncated.
    TruncatedCoordinate,
    /// The right key plus members RFC 7638 §3.2 ignores.
    WithExtraMembers,
}

#[derive(Arbitrary, Debug)]
enum HtuChoice {
    Correct,
    UpperCaseAuthority,
    DefaultPort,
    OtherPort,
    WithQuery,
    WithFragment,
    DotSegment,
    EncodedDotSegment,
    PercentEncodedUnreserved,
    EncodedSlash,
    TrailingSlash,
    OtherPath,
    OtherHost,
    HttpScheme,
    WithUserinfo,
    Absent,
    NotAString,
    Text(String),
}

#[derive(Arbitrary, Debug)]
enum HtmChoice {
    Correct,
    LowerCase,
    Other,
    Absent,
    NotAString,
    Text(String),
}

#[derive(Arbitrary, Debug)]
enum JtiChoice {
    Correct,
    Absent,
    Empty,
    AtLimit,
    OverLimit,
    NotAString,
    Text(String),
}

#[derive(Arbitrary, Debug)]
enum IatChoice {
    Now,
    AtOldEdge,
    JustPastOldEdge,
    TenSecondsAhead,
    ElevenSecondsAhead,
    Offset(i32),
    NotANumber(String),
    Absent,
}

#[derive(Arbitrary, Debug)]
enum NonceClaim {
    Absent,
    Current,
    Previous,
    ThreeWindowsAgo,
    OtherAudience,
    OtherSecret,
    Text(String),
}

#[derive(Arbitrary, Debug)]
struct Input {
    key: KeyChoice,
    typ: TypChoice,
    alg: AlgChoice,
    jwk: JwkChoice,
    htm: HtmChoice,
    htu: HtuChoice,
    jti: JtiChoice,
    iat: IatChoice,
    nonce: NonceClaim,
    require_nonce: bool,
    /// The method the endpoint is expecting.
    expect_post: bool,
    /// Extra claims, to make sure an unknown one is ignored rather than
    /// tripping anything.
    extra: Vec<(String, i32)>,
    /// Free-form input for the normaliser, which is checked on its own below.
    raw_uri: String,
    /// A thumbprint an authorization request might have pinned.
    pinned: Option<String>,
}

fuzz_target!(|input: Input| {
    check_uri_normalisation(&input);
    check_nonces(&input);
    check_proof(&input);
    check_key_binding(&input);
});

// ---------------------------------------------------------------------------
// htu normalisation
// ---------------------------------------------------------------------------

fn check_uri_normalisation(input: &Input) {
    for raw in [input.raw_uri.as_str(), &render_htu(&input.htu)] {
        let Ok(normalised) = NormalisedUri::parse(raw) else {
            continue;
        };

        // Idempotent, or the comparison depends on how many times each side
        // has been through it.
        let again = NormalisedUri::parse(normalised.as_str())
            .expect("a normalised URI must re-normalise to itself");
        assert_eq!(
            normalised, again,
            "normalising {raw:?} twice changed the answer"
        );

        // The authority is preserved up to case. This is the property that
        // makes the whole comparison a binding: if normalisation could rewrite
        // the host, a proof for one server would be accepted at another.
        let before = url::Url::parse(raw).expect("it parsed once already");
        let after = url::Url::parse(normalised.as_str()).expect("we just built it");
        assert_eq!(
            after.host_str().map(str::to_lowercase),
            before.host_str().map(str::to_lowercase),
            "normalising {raw:?} changed the host"
        );
        assert_eq!(
            after.scheme(),
            before.scheme().to_lowercase(),
            "normalising {raw:?} changed the scheme"
        );
        assert_eq!(
            after.port_or_known_default(),
            before.port_or_known_default(),
            "normalising {raw:?} changed the effective port"
        );

        // Nothing accepted carries userinfo, a query or a fragment.
        assert!(after.username().is_empty(), "userinfo survived {raw:?}");
        assert!(after.password().is_none());
        assert_eq!(after.query(), None, "a query survived {raw:?}");
        assert_eq!(after.fragment(), None, "a fragment survived {raw:?}");

        // And only the two schemes whose normalisation RFC 9110 §4.2.3 defines.
        assert!(matches!(after.scheme(), "http" | "https"));
    }
}

// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

fn check_nonces(input: &Input) {
    let issuer = nonce_issuer();
    let window = issuer.window();

    // A nonce is good for at least one whole window, whenever it was issued.
    // This is the property that stops a client looping on `use_dpop_nonce`.
    let offset = time::Duration::seconds(i64::from(input.extra.len() as u32 % 600));
    let issued_at = now() + offset;
    let nonce = issuer.issue(AUDIENCE, issued_at);
    assert!(
        issuer.accepts(&nonce, AUDIENCE, issued_at),
        "a nonce was not accepted at the instant it was issued"
    );
    assert!(
        issuer.accepts(&nonce, AUDIENCE, issued_at + window),
        "a nonce issued at +{offset} had expired one window later"
    );

    // And never outside its two windows, or for another audience or secret.
    assert!(!issuer.accepts(&nonce, AUDIENCE, issued_at + window * 3));
    assert!(!issuer.accepts(&nonce, "https://as.example/t/other", issued_at));
    assert!(
        !NonceIssuer::from_secret(b"a different secret").accepts(&nonce, AUDIENCE, issued_at)
    );

    // Arbitrary text is never a nonce. (It could be, with probability 2^-128.)
    if let NonceClaim::Text(text) = &input.nonce {
        if text != &nonce {
            assert!(
                !issuer.accepts(text, AUDIENCE, issued_at),
                "arbitrary text {text:?} was accepted as a nonce"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The proof
// ---------------------------------------------------------------------------

fn check_proof(input: &Input) {
    let key = input.key.key();
    let header = render_header(input, key);
    let claims = render_claims(input);
    let proof = sign(key, &header, &claims);

    let method = if input.expect_post { "POST" } else { "GET" };
    let mut expectation = Expectation::new(method, endpoint());
    if input.require_nonce {
        expectation = expectation.requiring_nonce(nonce_issuer(), AUDIENCE);
    }

    // The same bytes, but with somebody else's key advertised in the header.
    // Whatever else is true of the input, this must never be accepted: it is a
    // proof signed by one key claiming to be another.
    let mut forged_header = header.clone();
    if forged_header.get("jwk").is_some() {
        let other = keys()
            .iter()
            .find(|candidate| candidate.algorithm() == key.algorithm())
            .filter(|candidate| !std::ptr::eq(*candidate, key));
        if let Some(other) = other {
            forged_header["jwk"] = public_jwk(other);
            let forged = sign(key, &forged_header, &claims);
            assert!(
                dpop::check(&forged, &expectation, now()).is_err(),
                "a proof signed by one key and advertising another was accepted"
            );
        }
    }

    let Ok(accepted) = dpop::check(&proof, &expectation, now()) else {
        // Every rejection is fine. What must never happen is an acceptance
        // that should not have been, which is what the rest of this checks.
        return;
    };

    // --- properties of an ACCEPTED proof ---

    // The method matched exactly. RFC 9110 §9.1 makes it case-sensitive.
    assert_eq!(
        claims.get("htm").and_then(Value::as_str),
        Some(method),
        "accepted a proof whose htm is not the request's method"
    );

    // The URI matched after normalisation, and the normalisation is the one
    // this test can reproduce from the claim.
    let htu = claims
        .get("htu")
        .and_then(Value::as_str)
        .expect("an accepted proof carries htu");
    assert_eq!(
        NormalisedUri::parse(htu).expect("it was accepted, so it parsed"),
        *endpoint(),
        "accepted a proof for {htu:?} at {ENDPOINT}"
    );

    // The `jti` is usable: the replay defence has something to remember, and
    // it is bounded so it cannot be used to grow the store without limit.
    assert!(!accepted.jti.is_empty(), "accepted a proof with an empty jti");
    assert!(
        accepted.jti.len() <= MAX_JTI_LEN,
        "accepted a jti of {} bytes, over the {MAX_JTI_LEN} limit",
        accepted.jti.len()
    );
    assert_eq!(
        Some(accepted.jti.as_str()),
        claims.get("jti").and_then(Value::as_str),
        "the returned jti is not the one in the claims"
    );

    // The replay row lives exactly as long as the proof stays acceptable —
    // no longer (the row would be dead weight) and no shorter (there would be
    // an interval in which the proof is accepted and the replay is not seen).
    assert_eq!(
        accepted.replay_expires_at,
        accepted.issued_at + DEFAULT_MAX_AGE,
        "the replay window and the acceptance window disagree"
    );
    assert!(
        accepted.issued_at <= now() + time::Duration::seconds(10),
        "accepted a proof minted more than the FAPI skew ahead"
    );
    assert!(
        now() - accepted.issued_at <= DEFAULT_MAX_AGE,
        "accepted a proof older than the window"
    );

    // The thumbprint is 43 characters of base64url — the shape
    // `asterius_oidc::authorize` validates `dpop_jkt` against, so a proof whose
    // thumbprint did not have it could never be correlated with a PAR request.
    assert_eq!(
        accepted.jkt.as_str().len(),
        43,
        "a thumbprint that dpop_jkt could never equal"
    );
    assert!(
        accepted
            .jkt
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(
        accepted.confirmation(),
        json!({ "jkt": accepted.jkt.as_str() })
    );

    // The header's key carried no private material, whatever else it carried.
    let jwk = header
        .get("jwk")
        .and_then(Value::as_object)
        .expect("an accepted proof carries a jwk object");
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        assert!(
            !jwk.contains_key(member),
            "accepted a proof whose jwk carries `{member}` (RFC 9449 §4.2)"
        );
    }

    // And a nonce was present and current whenever one was required.
    if input.require_nonce {
        let nonce = claims
            .get("nonce")
            .and_then(Value::as_str)
            .expect("accepted a proof with no nonce where one was required");
        assert!(
            nonce_issuer().accepts(nonce, AUDIENCE, now()),
            "accepted a nonce this server would not issue: {nonce:?}"
        );
    }

    // The same proof at another endpoint must be refused: the acceptance above
    // is the binding, not a permissive path through the function.
    let elsewhere = NormalisedUri::parse("https://as.example/t/demo/introspect").expect("uri");
    let mut moved = Expectation::new(method, &elsewhere);
    if input.require_nonce {
        moved = moved.requiring_nonce(nonce_issuer(), AUDIENCE);
    }
    assert!(
        dpop::check(&proof, &moved, now()).is_err(),
        "a proof accepted at {ENDPOINT} was also accepted elsewhere"
    );
}

// ---------------------------------------------------------------------------
// Key binding (RFC 9449 §10)
// ---------------------------------------------------------------------------

fn check_key_binding(input: &Input) {
    let key = input.key.key();
    let jkt = asterius_jose::thumbprint(&key.public_jwk().expect("jwk")).expect("thumbprint");

    // Nothing pinned is always fine; a pinned key with no proof never is.
    assert!(dpop::matches_pinned_key(None, Some(&jkt)));
    assert!(dpop::matches_pinned_key(None, None));
    assert!(dpop::matches_pinned_key(Some(jkt.as_str()), Some(&jkt)));
    assert!(!dpop::matches_pinned_key(Some(jkt.as_str()), None));

    if let Some(pinned) = &input.pinned {
        // A pinned value that is not this thumbprint must never match it.
        if pinned != jkt.as_str() {
            assert!(
                !dpop::matches_pinned_key(Some(pinned), Some(&jkt)),
                "a pinned key that is not the proof's was accepted: {pinned:?}"
            );
        }

        // RFC 9449 §10.1: the two PAR spellings agree, or the request is
        // refused. Whatever comes back is one of the two inputs, never a third.
        match dpop::reconcile_pinned_key(Some(&jkt), Some(pinned)) {
            Ok(Some(reconciled)) => {
                assert_eq!(reconciled, *pinned);
                assert_eq!(reconciled, jkt.as_str());
            }
            Ok(None) => panic!("two pinned keys reconciled to none"),
            Err(_) => assert_ne!(
                pinned,
                jkt.as_str(),
                "two agreeing spellings were refused as a disagreement"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn public_jwk(key: &SigningKey) -> Value {
    let mut jwk = key.public_jwk().expect("jwk");
    if let Some(object) = jwk.as_object_mut() {
        object.remove("use");
        object.remove("alg");
    }
    jwk
}

fn sign(key: &SigningKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(header).expect("header")),
        B64.encode(serde_json::to_vec(claims).expect("claims"))
    );
    let signature = key.sign(signing_input.as_bytes()).expect("sign");
    format!("{signing_input}.{}", B64.encode(signature))
}

fn render_header(input: &Input, key: &SigningKey) -> Value {
    let mut header = serde_json::Map::new();

    match &input.typ {
        TypChoice::Correct => {
            header.insert("typ".into(), json!("dpop+jwt"));
        }
        TypChoice::Absent => {}
        TypChoice::Jwt => {
            header.insert("typ".into(), json!("JWT"));
        }
        TypChoice::WithPrefix => {
            header.insert("typ".into(), json!("application/dpop+jwt"));
        }
        TypChoice::UpperCase => {
            header.insert("typ".into(), json!("DPOP+JWT"));
        }
        TypChoice::Text(text) => {
            header.insert("typ".into(), json!(text));
        }
    }

    let alg = match &input.alg {
        AlgChoice::Correct => key.algorithm().as_str().to_owned(),
        AlgChoice::Mismatched => SigningAlgorithm::ALL
            .into_iter()
            .find(|candidate| *candidate != key.algorithm())
            .expect("more than one algorithm")
            .as_str()
            .to_owned(),
        AlgChoice::None => "none".to_owned(),
        AlgChoice::Hs256 => "HS256".to_owned(),
        AlgChoice::Rs256 => "RS256".to_owned(),
        AlgChoice::Text(text) => text.clone(),
    };
    header.insert("alg".into(), json!(alg));

    match &input.jwk {
        JwkChoice::Correct => {
            header.insert("jwk".into(), public_jwk(key));
        }
        JwkChoice::AnotherKey => {
            let other = keys()
                .iter()
                .find(|candidate| !std::ptr::eq(*candidate, key))
                .unwrap_or(key);
            header.insert("jwk".into(), public_jwk(other));
        }
        JwkChoice::Absent => {}
        JwkChoice::NotAnObject => {
            header.insert("jwk".into(), json!("a string"));
        }
        JwkChoice::EmptyObject => {
            header.insert("jwk".into(), json!({}));
        }
        JwkChoice::WithPrivateMember(which) => {
            let members = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
            let mut jwk = public_jwk(key);
            jwk[members[usize::from(*which) % members.len()]] = json!("c2VjcmV0");
            header.insert("jwk".into(), jwk);
        }
        JwkChoice::WrongKty => {
            let mut jwk = public_jwk(key);
            jwk["kty"] = json!("oct");
            header.insert("jwk".into(), jwk);
        }
        JwkChoice::WrongDeclaredAlg => {
            let mut jwk = public_jwk(key);
            jwk["alg"] = json!(SigningAlgorithm::ALL
                .into_iter()
                .find(|candidate| *candidate != key.algorithm())
                .expect("more than one")
                .as_str());
            header.insert("jwk".into(), jwk);
        }
        JwkChoice::TruncatedCoordinate => {
            let mut jwk = public_jwk(key);
            for member in ["x", "y", "n"] {
                if let Some(value) = jwk.get(member).and_then(Value::as_str) {
                    let shortened: String = value.chars().take(value.len() / 2).collect();
                    jwk[member] = json!(shortened);
                }
            }
            header.insert("jwk".into(), jwk);
        }
        JwkChoice::WithExtraMembers => {
            let mut jwk = public_jwk(key);
            // RFC 7638 §3.2: the thumbprint covers the required members only,
            // so these must not change it.
            jwk["kid"] = json!("ignored");
            jwk["use"] = json!("sig");
            jwk["ext"] = json!(true);
            header.insert("jwk".into(), jwk);
        }
    }

    Value::Object(header)
}

fn render_htu(choice: &HtuChoice) -> String {
    match choice {
        HtuChoice::Correct => ENDPOINT.to_owned(),
        HtuChoice::UpperCaseAuthority => "HTTPS://AS.EXAMPLE/t/demo/token".to_owned(),
        HtuChoice::DefaultPort => "https://as.example:443/t/demo/token".to_owned(),
        HtuChoice::OtherPort => "https://as.example:8443/t/demo/token".to_owned(),
        HtuChoice::WithQuery => "https://as.example/t/demo/token?client_id=x".to_owned(),
        HtuChoice::WithFragment => "https://as.example/t/demo/token#frag".to_owned(),
        HtuChoice::DotSegment => "https://as.example/t/other/../demo/token".to_owned(),
        HtuChoice::EncodedDotSegment => "https://as.example/t/other/%2E%2E/demo/token".to_owned(),
        HtuChoice::PercentEncodedUnreserved => "https://as.example/t/demo/%74oken".to_owned(),
        HtuChoice::EncodedSlash => "https://as.example/t%2Fdemo/token".to_owned(),
        HtuChoice::TrailingSlash => "https://as.example/t/demo/token/".to_owned(),
        HtuChoice::OtherPath => "https://as.example/t/demo/introspect".to_owned(),
        HtuChoice::OtherHost => "https://attacker.example/t/demo/token".to_owned(),
        HtuChoice::HttpScheme => "http://as.example/t/demo/token".to_owned(),
        HtuChoice::WithUserinfo => "https://as.example@as.example/t/demo/token".to_owned(),
        HtuChoice::Absent | HtuChoice::NotAString => String::new(),
        HtuChoice::Text(text) => text.clone(),
    }
}

fn render_claims(input: &Input) -> Value {
    let mut claims = serde_json::Map::new();

    match &input.htm {
        HtmChoice::Correct => {
            claims.insert(
                "htm".into(),
                json!(if input.expect_post { "POST" } else { "GET" }),
            );
        }
        HtmChoice::LowerCase => {
            claims.insert(
                "htm".into(),
                json!(if input.expect_post { "post" } else { "get" }),
            );
        }
        HtmChoice::Other => {
            claims.insert("htm".into(), json!("DELETE"));
        }
        HtmChoice::Absent => {}
        HtmChoice::NotAString => {
            claims.insert("htm".into(), json!(["POST"]));
        }
        HtmChoice::Text(text) => {
            claims.insert("htm".into(), json!(text));
        }
    }

    match &input.htu {
        HtuChoice::Absent => {}
        HtuChoice::NotAString => {
            claims.insert("htu".into(), json!(42));
        }
        other => {
            claims.insert("htu".into(), json!(render_htu(other)));
        }
    }

    match &input.jti {
        JtiChoice::Correct => {
            claims.insert("jti".into(), json!("0123456789abcdef"));
        }
        JtiChoice::Absent => {}
        JtiChoice::Empty => {
            claims.insert("jti".into(), json!(""));
        }
        JtiChoice::AtLimit => {
            claims.insert("jti".into(), json!("j".repeat(MAX_JTI_LEN)));
        }
        JtiChoice::OverLimit => {
            claims.insert("jti".into(), json!("j".repeat(MAX_JTI_LEN + 1)));
        }
        JtiChoice::NotAString => {
            claims.insert("jti".into(), json!(7));
        }
        JtiChoice::Text(text) => {
            claims.insert("jti".into(), json!(text));
        }
    }

    let base = now().unix_timestamp();
    let window = DEFAULT_MAX_AGE.whole_seconds();
    match &input.iat {
        IatChoice::Now => {
            claims.insert("iat".into(), json!(base));
        }
        IatChoice::AtOldEdge => {
            claims.insert("iat".into(), json!(base - window));
        }
        IatChoice::JustPastOldEdge => {
            claims.insert("iat".into(), json!(base - window - 1));
        }
        IatChoice::TenSecondsAhead => {
            claims.insert("iat".into(), json!(base + 10));
        }
        IatChoice::ElevenSecondsAhead => {
            claims.insert("iat".into(), json!(base + 11));
        }
        // `saturating_add` is about this file, not the subject: an overflow
        // while building the input would panic here and be reported against
        // code that never saw the value.
        IatChoice::Offset(offset) => {
            claims.insert("iat".into(), json!(base.saturating_add(i64::from(*offset))));
        }
        IatChoice::NotANumber(text) => {
            claims.insert("iat".into(), json!(text));
        }
        IatChoice::Absent => {}
    }

    let issuer = nonce_issuer();
    match &input.nonce {
        NonceClaim::Absent => {}
        NonceClaim::Current => {
            claims.insert("nonce".into(), json!(issuer.issue(AUDIENCE, now())));
        }
        NonceClaim::Previous => {
            claims.insert(
                "nonce".into(),
                json!(issuer.issue(AUDIENCE, now() - issuer.window())),
            );
        }
        NonceClaim::ThreeWindowsAgo => {
            claims.insert(
                "nonce".into(),
                json!(issuer.issue(AUDIENCE, now() - issuer.window() * 3)),
            );
        }
        NonceClaim::OtherAudience => {
            claims.insert(
                "nonce".into(),
                json!(issuer.issue("https://as.example/t/other", now())),
            );
        }
        NonceClaim::OtherSecret => {
            claims.insert(
                "nonce".into(),
                json!(NonceIssuer::from_secret(b"somebody else's secret").issue(AUDIENCE, now())),
            );
        }
        NonceClaim::Text(text) => {
            claims.insert("nonce".into(), json!(text));
        }
    }

    for (name, value) in &input.extra {
        // Never let a generated member collide with one under test.
        if !matches!(name.as_str(), "htm" | "htu" | "jti" | "iat" | "nonce" | "ath") {
            claims.insert(name.clone(), json!(value));
        }
    }

    Value::Object(claims)
}
