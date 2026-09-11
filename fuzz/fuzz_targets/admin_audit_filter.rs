//! The admin API's audit filter: the query string of `GET /audit/events` and
//! `GET /audit/events/export` (`ast-lh3.9`).
//!
//! A query string is text somebody typed, and it is the one input that
//! decides which records of the trail — the most sensitive thing a read
//! scope reaches — an operator is shown. What reaches the database is the
//! parsed [`AuditFilter`], bound as parameters; this target is about the
//! parse.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes are a query string and parsing one must not
//!   panic, whatever the percent-encoding does.
//! * **Closed.** Every accepted filter names only parameters the documented
//!   list has: a value in an accepted filter came from a documented
//!   parameter, never from a misspelling that was quietly ignored.
//! * **Typed.** An accepted `grant` is a UUID in the spelling the column
//!   holds; an accepted `type` is one of `EventType::ALL`; an accepted window
//!   is ordered.
//! * **Bounded.** No accepted value is over `MAX_VALUE_LEN` or carries a
//!   control character, and no accepted filter names more than `MAX_TYPES`
//!   types.
//! * **Silent about the value.** A refusal names the parameter and never
//!   echoes what was sent: the message is rendered to whoever asked.
#![no_main]

use asterius_admin_api::audit::{MAX_TYPES, MAX_VALUE_LEN, PARAMETERS, parse_filter};
use asterius_domain::audit::EventType;
use libfuzzer_sys::fuzz_target;

/// The refusals that name no parameter.
const CONSTANT_REFUSALS: &[&str] = &[
    "grant must be a UUID",
    "type may be given at most 64 times",
    "type is not an event type this server records",
    "from must be before until",
    "unknown filter parameter; see the OpenAPI document for the list",
];

/// The refusals that start with a documented parameter's name.
const NAMED_REFUSALS: &[&str] = &[
    " is longer than 256 bytes",
    " must be a non-empty value",
    " may be given once",
    " must be an RFC 3339 instant",
];

fuzz_target!(|data: &[u8]| {
    let Ok(query) = std::str::from_utf8(data) else {
        return;
    };

    match parse_filter(query) {
        Ok(filter) => {
            // Closed: every non-empty pair of an accepted query is a documented
            // parameter or one of the listing's own.
            for pair in query.split('&').filter(|pair| !pair.is_empty()) {
                let name = pair.split_once('=').map_or(pair, |(name, _)| name);
                assert!(
                    matches!(name, "cursor" | "limit")
                        || PARAMETERS.iter().any(|(known, _)| *known == name),
                    "accepted an undocumented parameter {name:?} in {query:?}"
                );
            }

            // Typed.
            if let Some(grant) = &filter.grant {
                let parsed: uuid::Uuid =
                    grant.as_str().parse().expect("an accepted grant is a UUID");
                assert_eq!(
                    parsed.to_string(),
                    grant.as_str(),
                    "a grant was not normalised"
                );
            }
            for event_type in &filter.event_types {
                assert!(EventType::ALL.contains(event_type));
            }
            assert!(filter.event_types.len() <= MAX_TYPES);
            if let (Some(from), Some(until)) = (filter.from, filter.until) {
                assert!(from < until, "accepted an empty or inverted window");
            }

            // Bounded.
            for value in [
                filter.agent.as_ref().map(|id| id.as_str().to_owned()),
                filter.owner.clone(),
                filter.user.clone(),
            ]
            .into_iter()
            .flatten()
            {
                assert!(!value.is_empty(), "accepted an empty identifier");
                assert!(value.len() <= MAX_VALUE_LEN, "accepted an over-long value");
                assert!(
                    !value.chars().any(char::is_control),
                    "accepted a control character"
                );
            }
        }
        Err(error) => {
            // Silent about the value: a refusal is one of a closed set of
            // sentences, each naming at most a documented parameter — never
            // the bytes that were sent, which are rendered to whoever asked.
            let message = error.to_string();
            let constant = CONSTANT_REFUSALS.contains(&message.as_str());
            let named = PARAMETERS.iter().any(|(name, _)| {
                message
                    .strip_prefix(name)
                    .is_some_and(|rest| NAMED_REFUSALS.contains(&rest))
            });
            assert!(
                constant || named,
                "a refusal outside the closed set: {message:?}"
            );
        }
    }
});
