//! `RedirectUri::parse` and the comparison built on it — RFC 6749 §3.1.2.2–3,
//! RFC 9700 §4.1.3, RFC 8252 §7.3, FAPI 2.0 SP §5.3.2.2 item 8.
//!
//! A redirect URI is where the authorization code goes. Get the comparison
//! wrong and the code goes to the attacker, which is the whole of RFC 9700
//! §4.1. So this target does not feed random bytes at a URL parser and check
//! that nothing panics: random bytes are almost never a URI, and never two
//! URIs that a broken comparison would confuse. It builds a **pair** of URIs
//! from a small structured grammar — the same host in two spellings, the same
//! path with one byte changed, a port where a port may vary and a port where it
//! may not — and asserts, over that pair:
//!
//! * **Normalisation is never applied.** What `parse` accepts, it accepts byte
//!   for byte, and what a URL parser would rewrite it refuses. Both halves
//!   matter: rewriting changes what the client must send back, and storing a
//!   form the browser rewrites stores a string no request can carry.
//! * **A match is string equality, or it is a loopback port.** Two different
//!   strings may match only under RFC 8252 §7.3, and then only across the port
//!   — host, path and query stay byte-equal, so the exception cannot widen into
//!   the pattern matching RFC 9700 §4.1.3 removed.
//! * **The exception is native-only.** A web client gets `==` and nothing else,
//!   whatever it managed to register.
//! * **Matching is reflexive and symmetric.** Anything else means the
//!   authorization endpoint and the token endpoint can disagree about one URI.
//! * **An accepted URI is https, or loopback http on a native client**, has no
//!   fragment and no userinfo — the properties PAR and the token endpoint never
//!   re-check.
#![no_main]

use asterius_domain::{ApplicationType, RedirectUri};
use libfuzzer_sys::fuzz_target;

/// A structured URI generator: the fuzzer picks components, not characters.
///
/// The alternatives are chosen to be *near misses* of each other, because that
/// is the only input a comparison bug shows up on. Random strings agree on
/// nothing and so distinguish nothing.
struct Components<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Components<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// The next byte, wrapping round rather than running out: a short input
    /// still produces a whole URI, it just repeats itself.
    fn byte(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let byte = self.bytes[self.at % self.bytes.len()];
        self.at = self.at.wrapping_add(1);
        byte
    }

    fn pick<T: Copy>(&mut self, choices: &[T]) -> T {
        choices[usize::from(self.byte()) % choices.len()]
    }

    fn uri(&mut self) -> String {
        const SCHEMES: [&str; 6] = ["https", "http", "HTTPS", "com.example.app", "ftp", ""];
        const USERINFO: [&str; 3] = ["", "user@", "user:pw@"];
        // Two spellings of one IPv4 loopback, two of one IPv6 loopback, two of
        // one IDN host, plus the hosts the rules turn on.
        const HOSTS: [&str; 13] = [
            "127.0.0.1",
            "127.1",
            "127.0.0.2",
            "[::1]",
            "[0:0:0:0:0:0:0:1]",
            "localhost",
            "LOCALHOST",
            "rp.example",
            "RP.Example",
            "rp.example.evil",
            "xn--e1afmkfd.example",
            "пример.example",
            "",
        ];
        // Ports that may vary for loopback, ports a URL parser rewrites, and
        // strings that are not ports at all.
        const PORTS: [&str; 8] = ["", ":1", ":80", ":443", ":8443", ":51004", ":99999", ":"];
        const PATHS: [&str; 10] = [
            "", "/", "/cb", "/CB", "/cb/", "/cb2", "/a%2Fb", "/a%2fb", "/../cb", "/a/../cb",
        ];
        const QUERIES: [&str; 4] = ["", "?", "?x=1", "?X=1"];
        const FRAGMENTS: [&str; 3] = ["", "#", "#f"];

        let scheme = self.pick(&SCHEMES);
        let userinfo = self.pick(&USERINFO);
        let host = self.pick(&HOSTS);
        let port = self.pick(&PORTS);
        let path = self.pick(&PATHS);
        let query = self.pick(&QUERIES);
        let fragment = self.pick(&FRAGMENTS);
        format!("{scheme}://{userinfo}{host}{port}{path}{query}{fragment}")
    }
}

/// The comparison, restated from the specifications rather than from the
/// implementation: two URIs are the same iff their strings are equal
/// (RFC 3986 §6.2.1), or they are the same loopback callback on different ports
/// (RFC 8252 §7.3, §8.4). Deliberately built from different primitives to the
/// code under test, so that an oracle and its subject cannot share a mistake.
fn same_callback(registered: &str, presented: &str) -> bool {
    if registered == presented {
        return true;
    }
    let strip_port = |uri: &str| -> Option<(String, String)> {
        let rest = uri.strip_prefix("http://")?;
        let slash = rest.find('/')?;
        let (authority, tail) = rest.split_at(slash);
        let host = match authority.strip_prefix('[') {
            Some(_) => &authority[..=authority.find(']')?],
            None => authority.split(':').next()?,
        };
        Some((host.to_owned(), tail.to_owned()))
    };
    match (strip_port(registered), strip_port(presented)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut components = Components::new(data);
    // The first byte decides the client type, so one corpus entry exercises
    // both sides of the FAPI 2.0 SP §5.3.2.2 item 8 rule.
    let application_type = if components.byte() % 2 == 0 {
        ApplicationType::Web
    } else {
        ApplicationType::Native
    };
    let registered_raw = components.uri();
    let presented = components.uri();

    // Validation is a pure function of its inputs: registration, PAR and the
    // token endpoint have to reach the same answer.
    let outcome = RedirectUri::parse(&registered_raw, application_type);
    assert_eq!(
        outcome,
        RedirectUri::parse(&registered_raw, application_type),
        "parsing is not deterministic: {registered_raw:?}"
    );

    let Ok(registered) = outcome else { return };

    // --- what an accepted URI is ------------------------------------------
    assert_eq!(
        registered.as_str(),
        registered_raw,
        "a redirect URI was normalised on the way in"
    );
    assert!(
        !registered.as_str().contains('#'),
        "a fragment survived: {registered}"
    );
    let authority = registered
        .as_str()
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .unwrap_or_default();
    assert!(
        !authority.is_empty(),
        "a redirect URI with no authority was accepted: {registered}"
    );
    assert!(
        !authority.contains('@'),
        "userinfo survived: {registered}"
    );
    let is_loopback_http = registered.as_str().starts_with("http://127.")
        || registered.as_str().starts_with("http://[::1]");
    assert!(
        registered.as_str().starts_with("https://")
            || (application_type == ApplicationType::Native && is_loopback_http),
        "an http redirect URI was registered outside the loopback exception: {registered}"
    );
    // The accepted form is a fixed point, so a stored URI re-validated on its
    // way out of the database comes back the same (`ast-83p.3`).
    assert_eq!(
        RedirectUri::parse(registered.as_str(), application_type).as_ref(),
        Ok(&registered),
        "an accepted redirect URI did not re-parse to itself"
    );

    // --- what matching is --------------------------------------------------
    assert!(
        registered.matches(registered.as_str(), application_type),
        "a registered URI did not match itself: {registered}"
    );
    assert!(
        RedirectUri::is_registered(
            std::slice::from_ref(&registered),
            registered.as_str(),
            application_type,
        ),
        "the set-level comparison disagrees with the single one: {registered}"
    );
    assert!(
        !RedirectUri::is_registered(&[], registered.as_str(), application_type),
        "an empty registered set matched something"
    );

    let matched = registered.matches(&presented, application_type);
    if matched && registered.as_str() != presented {
        // The only way two different strings may match (RFC 8252 §7.3).
        assert_eq!(
            application_type,
            ApplicationType::Native,
            "a web client got the loopback port exception: {registered} ~ {presented:?}"
        );
        assert!(
            same_callback(registered.as_str(), &presented),
            "a match changed more than the port: {registered} ~ {presented:?}"
        );
        // Anything matched must itself have been registrable, or the server
        // would accept at PAR what it refuses at registration.
        let round_trip = RedirectUri::parse(&presented, application_type)
            .expect("a matched redirect URI must be registrable");
        // Matching is symmetric: the two endpoints must not disagree about
        // which of a pair is "the" registered one.
        assert!(
            round_trip.matches(registered.as_str(), application_type),
            "matching is not symmetric: {registered} ~ {presented:?}"
        );
    }
    if !matched && registered.as_str() == presented {
        panic!("string equality did not match: {registered}");
    }

    // The hand-written relation and the implementation must agree in both
    // directions, for every pair the generator can produce.
    if let Ok(presented_uri) = RedirectUri::parse(&presented, application_type) {
        assert_eq!(
            matched,
            same_callback(registered.as_str(), presented_uri.as_str()),
            "the comparison disagrees with RFC 3986 §6.2.1 plus RFC 8252 §7.3: \
             {registered} ~ {presented_uri}"
        );
    }
});
