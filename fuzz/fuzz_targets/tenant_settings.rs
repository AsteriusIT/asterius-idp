//! `TenantSettings::from_json` — the parser every tenant's settings row goes
//! through, and the validator every admin API write goes through.
//!
//! A `tenants.settings` document is not client input, which is the reason to
//! fuzz it rather than a reason not to: it is a `jsonb` column edited by a
//! migration, a seed script, a support tool, or somebody in a `psql` session
//! during an incident. What comes back out of it decides how long an
//! authorization code lives.
//!
//! The properties asserted here are the ones nothing downstream re-checks:
//!
//! * **A parse cannot yield settings the profile forbids.** Whatever the
//!   stored document says, an accepted [`TenantSettings`] is within FAPI 2.0
//!   Security Profile §5.3.2.1 item 11's sixty seconds and within this
//!   server's access-token ceiling. A row edited by hand is not a way past a
//!   cap the API enforces.
//! * **What is accepted round-trips.** Reading, writing and reading again
//!   yields the same value, so a settings screen that saves what it loaded
//!   cannot drift.
//! * **A tenant's flags never widen the deployment's.** `effective_capabilities`
//!   may only subtract: whatever is parsed, no feature the deployment has
//!   switched off comes back on.
//! * **It never panics.** A panic here is a 500 on the discovery endpoint of
//!   every tenant whose row is affected.
#![no_main]

use asterius_domain::entities::tenant_settings::{
    MAX_ACCESS_TOKEN_LIFETIME, MAX_AUTHORIZATION_CODE_LIFETIME, MIN_LIFETIME,
};
use asterius_domain::{Capabilities, Feature, TenantSettings};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };

    let Ok(settings) = TenantSettings::from_json(Some(&value)) else {
        return;
    };

    let lifetimes = settings.lifetimes();
    assert!(
        lifetimes.authorization_code() <= MAX_AUTHORIZATION_CODE_LIFETIME
            && lifetimes.authorization_code() >= MIN_LIFETIME,
        "a stored document produced a code lifetime outside the profile's cap: {value}"
    );
    assert!(
        lifetimes.access_token() <= MAX_ACCESS_TOKEN_LIFETIME
            && lifetimes.access_token() >= MIN_LIFETIME,
        "a stored document produced an access token lifetime outside the cap: {value}"
    );

    let round_tripped =
        TenantSettings::from_json(Some(&settings.to_json())).expect("what was written parses");
    assert_eq!(round_tripped, settings, "settings did not round-trip");

    // Subtraction only: nothing a document says can switch a deployment
    // feature on.
    let off = Capabilities::default();
    assert_eq!(settings.effective_capabilities(off), off);
    for feature in Feature::ALL {
        assert!(
            !settings.effective_capabilities(off).is_enabled(feature),
            "a stored document enabled {feature}, which no tenant may do"
        );
    }
});
