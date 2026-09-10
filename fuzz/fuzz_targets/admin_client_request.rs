//! The body the console's client screen posts, and the document it reads back.
//!
//! `ast-f7m.5` puts a second door on the `clients` table: dynamic client
//! registration was the first, and the admin API is the second. The whole point
//! of the design is that the second door has no lock of its own — it calls
//! [`ClientRegistration::from_json`], the validator RFC 7591 registration calls
//! — so what is left to fuzz is the thin layer around it and the rendering that
//! answers.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes are a request body. Reading the `status` member
//!   out of one must not panic, whatever the bytes are.
//! * **The status vocabulary is closed.** Only `active` and `disabled` exist
//!   (`asterius_domain::ClientStatus`), and a body naming anything else must be
//!   refused rather than defaulted — the nearest wrong answer to "suspended" is
//!   "active", which is the opposite of what was asked for.
//! * **The edit form round-trips.** Whatever document the validator accepts, the
//!   admin API's rendering of the resulting client must validate *back* to the
//!   same registration. This is the property that keeps opening a client and
//!   pressing Save from rewriting it, and it is stated here over every document
//!   the validator accepts rather than over the handful in the unit tests.
//! * **No credential member is ever rendered.** This server issues no
//!   `client_secret` (FAPI 2.0 SP §5.3.2.1), and a client created from the
//!   console gets no registration access token (OIDC Registration §3.2: both or
//!   neither). Asserted over the documents' *members* rather than over their
//!   text, because `client_name` is free text: a client called
//!   "client_secret rotation service" is a rendering of a name, not of a
//!   credential, and a substring check would call it a finding.
#![no_main]

use asterius_admin_api::clients::{document, matches, requested_status, search_term, summarise};
use asterius_domain::{Capabilities, Client, ClientId, ClientRegistration, ClientStatus, TenantId};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

fuzz_target!(|data: &[u8]| {
    // 0. The search term, over arbitrary query-string bytes. It cannot fail
    //    and must not panic on a truncated or invalid escape, because a search
    //    box is not a place to answer a person with a 400.
    if let Ok(raw) = std::str::from_utf8(data) {
        let term = search_term(raw);
        assert!(
            term.len() <= raw.len().saturating_mul(3),
            "decoding a search term grew it"
        );
    }

    // 1. The status member, over arbitrary bytes.
    match requested_status(data) {
        Err(_) => {}
        Ok(None) => {}
        Ok(Some(status)) => assert!(
            matches!(status, ClientStatus::Active | ClientStatus::Disabled),
            "a status outside the closed set came out of a request body"
        ),
    }

    // 2. Everything else is about a document the validator accepted. A
    //    rejected one is not a client and there is nothing to render.
    let Ok(registration) = ClientRegistration::from_json(data, Capabilities::default()) else {
        return;
    };

    let client = Client {
        tenant: TenantId::new("demo"),
        id: ClientId::mint(),
        registration: registration.clone(),
        status: ClientStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    };

    let rendered = document(&client);
    let round_tripped =
        ClientRegistration::from_json(rendered.to_string().as_bytes(), Capabilities::default())
            .expect("a rendered registration must be a document this server would accept");
    assert_eq!(
        round_tripped, registration,
        "the edit form's document does not round-trip"
    );

    // 3. A client is findable by the name it holds and by the identifier it
    //    was given. A search that could not find a client by its own name is
    //    the failure an operator meets while looking at the row.
    assert!(matches(&client, ""), "an empty search hid a client");
    assert!(
        matches(&client, &registration.client_name),
        "a client is not findable by its own name"
    );
    assert!(
        matches(&client, client.id.as_str()),
        "a client is not findable by its own client_id"
    );

    // 4. Neither document has a credential member. Both screens, because the
    //    inventory is the one nobody re-reads.
    let row = summarise(&client);
    for credential in ["client_secret", "registration_access_token"] {
        assert!(
            rendered.get(credential).is_none() && row.get(credential).is_none(),
            "the admin API rendered a {credential} member"
        );
    }
});
