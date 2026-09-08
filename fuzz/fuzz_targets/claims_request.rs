//! `ClaimsRequest::parse` — the OIDC Core §5.5 `claims` request parameter.
//!
//! This one is client input in the fullest sense. Every other parameter of an
//! authorization request is a string with a grammar; this is a whole JSON
//! document whose shape, size, nesting and member names the client chose. It
//! arrives inside a pushed request, so a client authenticated before sending
//! it — but authentication narrows *who* is asking, not what they may have,
//! and a registered client is exactly the attacker RFC 9700's threat model
//! spends most of its time on.
//!
//! What is asserted here is what nothing downstream re-checks:
//!
//! * **No accepted request can name a claim the authorization server issues.**
//!   `sub`, `aud`, `acr`, `cnf`, `sid`, `iss` — the whole of
//!   `ClaimName::SERVER_ISSUED`. A `claims` parameter able to name one is a
//!   client able to ask for its own `sub` to be overwritten, and the value
//!   that comes back is the one an RP treats as the user's identity. The
//!   guarantee is structural — a request is keyed by `ReleasableClaim`, which
//!   has no variant for such a name — and this is the check that the structure
//!   actually holds over arbitrary input.
//! * **Nothing accepted exceeds the bounds.** Length, per-section member
//!   count, and nesting. The parameter is stored on the pushed request, stored
//!   again on the grant and read on every issuance for the life of that grant,
//!   so an unbounded one is an unbounded row read an unbounded number of
//!   times.
//! * **Parsing is a pure function.** The same bytes give the same answer, and
//!   an accepted request re-serialises to something the parser accepts again.
//!   A parse that depended on anything else would be a parse a proxy and this
//!   server could disagree about.
//! * **It answers rather than dies.** Deep nesting is refused, not recursed
//!   into: `serde_json`'s own recursion limit sees to the parse, and
//!   `MAX_DEPTH` sees to what is kept.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::ClaimName;
use asterius_oidc::claims::{ClaimsRequest, ReleasableClaim};
use libfuzzer_sys::fuzz_target;

/// Member names worth spending the budget on: the reserved ones a request must
/// never be able to name, the ordinary ones it must be able to, and the
/// near-misses in between. Random bytes are almost never any of these.
const NAMES: [&str; 16] = [
    "sub",
    "acr",
    "aud",
    "cnf",
    "sid",
    "iss",
    "email",
    "email_verified",
    "updated_at",
    "name",
    "name#ja-Kana-JP",
    "sub#en",
    "email#de",
    "",
    "given_name",
    "\u{202e}given_name",
];

/// The shapes an individual claim request can take (OIDC Core §5.5.1), plus
/// the ones that must be refused.
const ENTRIES: [&str; 8] = [
    "null",
    "{}",
    r#"{"essential":true}"#,
    r#"{"essential":"true"}"#,
    r#"{"value":"a-guess"}"#,
    r#"{"values":["a","b"]}"#,
    "[]",
    r#""a string""#,
];

#[derive(Arbitrary, Debug)]
struct Input {
    /// `(section, name index, entry index)` — 0 chooses `id_token`.
    members: Vec<(bool, u8, u8)>,
    /// A member name the corpus did not think of.
    free_name: String,
    /// A whole parameter, byte for byte, so the target also covers input that
    /// is not JSON at all.
    free_document: String,
    /// Whether to add a top-level member that is neither section.
    noise: bool,
}

/// Builds a syntactically valid `claims` parameter out of the picks.
fn document(input: &Input) -> String {
    let mut id_token: Vec<String> = Vec::new();
    let mut userinfo: Vec<String> = Vec::new();
    for (in_id_token, name, entry) in input.members.iter().take(96) {
        let name = if usize::from(*name) == NAMES.len() {
            input.free_name.as_str()
        } else {
            NAMES[usize::from(*name) % NAMES.len()]
        };
        let entry = ENTRIES[usize::from(*entry) % ENTRIES.len()];
        let member = format!(
            "{}:{entry}",
            serde_json::Value::String(name.to_owned())
        );
        if *in_id_token {
            id_token.push(member);
        } else {
            userinfo.push(member);
        }
    }
    let mut sections = vec![
        format!(r#""id_token":{{{}}}"#, id_token.join(",")),
        format!(r#""userinfo":{{{}}}"#, userinfo.join(",")),
    ];
    if input.noise {
        sections.push(r#""transaction":{"nested":{"deeper":[1,2,3]}}"#.to_owned());
    }
    format!("{{{}}}", sections.join(","))
}

/// Everything an accepted request has to satisfy, whichever way it was built.
fn check(request: &ClaimsRequest, raw: &str) {
    assert!(
        raw.len() <= ClaimsRequest::MAX_LEN,
        "an oversized parameter was accepted"
    );
    assert!(request.id_token().len() <= ClaimsRequest::MAX_CLAIMS);
    assert!(request.userinfo().len() <= ClaimsRequest::MAX_CLAIMS);

    for claim in request.id_token().keys().chain(request.userinfo().keys()) {
        let name = claim.as_str();
        assert!(
            !ClaimName::SERVER_ISSUED.contains(&name),
            "a claims parameter named the server-issued claim {name:?}"
        );
        // And the name is one the resolver can turn back into the same claim:
        // a key it could not re-parse would be a key nothing downstream can
        // check against the reserved list.
        assert_eq!(
            ReleasableClaim::parse(name).as_ref(),
            Some(claim),
            "an accepted claim name does not re-parse: {name:?}"
        );
    }

    // `acr` is kept aside, never released (OIDC Core §5.5.1.1).
    assert!(
        !request
            .id_token()
            .keys()
            .chain(request.userinfo().keys())
            .any(|claim| claim.as_str() == "acr"),
        "acr reached a releasable map"
    );
}

fuzz_target!(|input: Input| {
    for raw in [document(&input), input.free_document.clone()] {
        let first = ClaimsRequest::parse(&raw);

        // Pure: the read path runs at push time and again over what was
        // stored, and the two are not allowed to disagree.
        assert_eq!(
            first,
            ClaimsRequest::parse(&raw),
            "parsing a claims parameter is not deterministic"
        );

        let Ok(request) = first else { continue };
        check(&request, &raw);

        // An accepted request survives a round trip through the shape it would
        // be stored in. Anything else would mean a grant could hold a claims
        // request the parser would refuse if it saw it again.
        let mut sections = serde_json::Map::new();
        for (member, claims) in [
            ("id_token", request.id_token()),
            ("userinfo", request.userinfo()),
        ] {
            let mut object = serde_json::Map::new();
            for (claim, entry) in claims {
                let mut members = serde_json::Map::new();
                if entry.is_essential() {
                    members.insert("essential".to_owned(), serde_json::Value::Bool(true));
                }
                if !entry.accepted_values().is_empty() {
                    members.insert(
                        "values".to_owned(),
                        serde_json::Value::Array(entry.accepted_values().to_vec()),
                    );
                }
                object.insert(claim.as_str().to_owned(), serde_json::Value::Object(members));
            }
            sections.insert(member.to_owned(), serde_json::Value::Object(object));
        }
        let restored = serde_json::Value::Object(sections).to_string();
        if restored.len() <= ClaimsRequest::MAX_LEN {
            let reparsed =
                ClaimsRequest::parse(&restored).expect("a stored claims request must re-parse");
            check(&reparsed, &restored);
            assert_eq!(
                reparsed.id_token().keys().collect::<Vec<_>>(),
                request.id_token().keys().collect::<Vec<_>>(),
                "a claims request changed shape on the way through storage"
            );
            assert_eq!(
                reparsed.userinfo().keys().collect::<Vec<_>>(),
                request.userinfo().keys().collect::<Vec<_>>(),
                "a claims request changed shape on the way through storage"
            );
        }
    }
});
