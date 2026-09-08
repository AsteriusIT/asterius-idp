//! The Content-Security-Policy every document this server renders is served
//! under, and the per-response nonce that makes it worth having.
//!
//! RFC 9700 §4.16 is the normative pressure: "Authorization servers MUST
//! prevent clickjacking attacks", and beyond the framing defence it says an
//! authorization server "SHOULD also use Content Security Policy (CSP) level 2
//! or greater" on the authorization endpoint "and, if applicable, other
//! endpoints used to authenticate the user and authorize the client (e.g., the
//! device authorization endpoint, login pages, error pages, etc.)". RFC 9700
//! §4.2.4 adds the other half: the pages around an authorization response
//! "SHOULD NOT include third-party resources or links to external sites",
//! because a third-party fetch is how `state`, a `request_uri` or a code leaks
//! through a `Referer`. `default-src 'none'` with only `'self'` fetch
//! directives is that sentence, enforced by the browser instead of by review.
//!
//! The policy is nonce-based rather than host-based, and the reason is in CSP
//! Level 3 §8.2: host- and path-based allow-lists are "brittle, awkward, and
//! difficult to implement and maintain", and the published bypasses of them are
//! bypasses of policies that looked strict. `'strict-dynamic'` then makes the
//! host list irrelevant — a browser that understands it ignores `'self'` and
//! every host expression for script — so what a page may execute is exactly
//! what this server put a nonce on, plus what that script loads itself.
//!
//! Nothing here is `'unsafe-inline'` or `'unsafe-eval'`, ever. A login page
//! that can run an attacker's inline script is a login page that can read the
//! password out of its own form, and `unsafe_keywords_appear_in_no_policy`
//! fails the build rather than trusting that nobody adds one later.

use asterius_domain::OpaqueToken;

/// How much entropy a nonce carries.
///
/// CSP Level 3 §7.1 ("Nonce Reuse"): a server delivering a nonce "MUST generate
/// a unique value each time it transmits a policy", and "the generated value
/// SHOULD be at least 128 bits long (before encoding), and SHOULD be generated
/// via a cryptographically secure random number generator in order to ensure
/// that the value is difficult for an attacker to predict".
///
/// This is that floor rather than [`DEFAULT_ENTROPY_BITS`] because the two
/// values defend different things. An opaque token is looked up by digest
/// across every token a deployment ever issues, so its bound is a collision and
/// 256 bits buys real headroom. A nonce is used once, is never stored, and is
/// published in the response that carries it: the only bound that matters is a
/// direct guess *before* that response is sent, and 128 bits is far past what
/// an attacker can search inside one request.
///
/// [`DEFAULT_ENTROPY_BITS`]: asterius_domain::credentials::DEFAULT_ENTROPY_BITS
const NONCE_BITS: usize = 128;

/// The value that appears in `script-src 'nonce-…'` and in the tags it allows.
///
/// A page and its policy have to agree, and the way they stop agreeing is that
/// somebody renders a page without one. So the nonce is a *type*, taken from
/// the request extensions that [`crate::document::layer`] populates, and
/// [`crate::document::Document`] cannot be constructed without one — a page
/// that forgot its nonce is not something a handler can write.
///
/// It is deliberately not a [`Secret`]: a nonce is public the moment the
/// response leaves, and pretending otherwise would only make it awkward to put
/// in the one place it has to go.
///
/// [`Secret`]: asterius_domain::Secret
#[derive(Debug, Clone)]
pub struct Nonce(String);

impl Nonce {
    /// Draws a nonce from the operating system CSPRNG.
    ///
    /// This borrows [`OpaqueToken`]'s generator rather than its secrecy: what
    /// is wanted is the CSPRNG and the `base64url` rendering, and reusing them
    /// means there is one place in this codebase where unguessable values come
    /// from, and one place to audit if that source is ever wrong.
    ///
    /// [`crate::document::layer`] is the only caller, and
    /// `the_nonce_generator_is_called_in_one_place` fails the build if a second
    /// one appears — a handler drawing its own nonce would render a page whose
    /// nonce is not the one in the header, which is a broken page rather than
    /// an insecure one, but is still a bug nobody should have to find twice.
    #[must_use]
    pub fn generate() -> Self {
        // CSP Level 3 §2.3.1: `base64-value = 1*( ALPHA / DIGIT / "+" / "/" /
        // "-" / "_" ) *2( "=" )`, so unpadded `base64url` is already inside the
        // grammar and needs no re-encoding.
        Self(
            OpaqueToken::generate_bits::<NONCE_BITS>()
                .expose()
                .to_owned(),
        )
    }

    /// A nonce with a chosen value, for tests that render a template.
    ///
    /// Test-only, and deliberately here rather than in the module that needs
    /// it: `source_audit` requires every real nonce to come from the document
    /// middleware, and this module is the one it exempts.
    #[cfg(test)]
    #[must_use]
    pub fn fixed_for_test(value: &str) -> Self {
        Self(value.to_owned())
    }

    /// The nonce as it appears inside `'nonce-…'`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `nonce="…"` attribute for a `<script>` or `<style>` tag.
    ///
    /// Rendering the attribute here rather than in each template keeps the
    /// quoting out of the templates: the value is `base64url`, so it cannot
    /// contain a quote, a space or a `>` to break out of the tag with — but
    /// that is a property of this type, and a template interpolating
    /// [`Self::as_str`] by hand would be one refactor away from not knowing it.
    #[must_use]
    pub fn attribute(&self) -> String {
        format!("nonce=\"{}\"", self.0)
    }
}

/// Longest origin accepted for `form-action`.
///
/// A registered `redirect_uri` is bounded long before it reaches here; this is
/// the backstop that keeps the header value bounded regardless.
const MAX_ORIGIN_LENGTH: usize = 255;

/// The longest a DNS name can be, and the longest one label of it can be.
const MAX_HOST_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;

/// An origin that may be named in `form-action`, alongside `'self'`.
///
/// This exists for `response_mode=form_post` (`ast-gxh.5`): that response is a
/// page this server renders which auto-submits a form to the *client's*
/// `redirect_uri`, so for that one page — and only that one — `form-action`
/// has to name the client's origin. Everything else stays `'self'`.
///
/// The origin comes from a registered `redirect_uri`, which is not attacker
/// controlled the way a query parameter is, but is attacker *supplied*: a
/// client registers it. A `;` or a newline that survived into the header would
/// let a registration append a directive to — or truncate — the policy of a
/// page this server serves. So it is parsed into a type before it can reach a
/// header, and the only strings that type can hold are ones containing no
/// character that means anything to a CSP parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormActionOrigin(String);

impl FormActionOrigin {
    /// Parses a serialized origin: a scheme, a host and an optional port.
    ///
    /// Deliberately not a URL parser. CSP's `host-source` grammar (CSP Level 3
    /// §2.3.1) is built from `host-char = ALPHA / DIGIT / "-"`, so an origin a
    /// URL parser would happily produce — an IPv6 literal, a percent-escape, a
    /// userinfo — is not expressible as a source expression at all. Accepting
    /// one here would mean emitting something the browser cannot read, and a
    /// policy a browser cannot read is a policy that does not apply.
    ///
    /// Nothing is rewritten, for the reason ADR-0005 rewrites nothing: an
    /// origin that is not already canonical is refused, so the string that was
    /// registered and the string that is served are the same string.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidOrigin`] for anything that is not exactly
    /// `https://host[:port]` — or `http://127.0.0.1[:port]`, which is the RFC
    /// 8252 §7.3 loopback callback a native client registers.
    // fuzz-target: csp_form_action
    pub fn parse(raw: &str) -> Result<Self, InvalidOrigin> {
        if raw.len() > MAX_ORIGIN_LENGTH {
            return Err(InvalidOrigin::TooLong);
        }
        let (scheme, authority) = raw.split_once("://").ok_or(InvalidOrigin::NotAnOrigin)?;

        // Split the port off before validating the host, so that a `:` left in
        // the host — an IPv6 literal, a userinfo password — fails the host
        // check rather than being read as a port.
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };

        if !is_canonical_host(host) {
            return Err(InvalidOrigin::Host);
        }
        match scheme {
            "https" => {}
            // RFC 8252 §7.3: a native client's callback is a loopback URI, and
            // it is `http`. Only the literal address, never `localhost`, which
            // resolves through DNS (RFC 8252 §8.3). The IPv6 loopback is absent
            // because `[::1]` cannot be written as a CSP `host-source`.
            "http" if host == "127.0.0.1" => {}
            _ => return Err(InvalidOrigin::Scheme),
        }
        if let Some(port) = port
            && !is_canonical_port(port)
        {
            return Err(InvalidOrigin::Port);
        }

        Ok(Self(raw.to_owned()))
    }

    /// The origin, as it appears in the policy.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `host` is an already-punycoded DNS name or an IPv4 literal, in the
/// one spelling this server accepts.
///
/// Lower case is required rather than folded: `Example.test` and `example.test`
/// are the same host, and normalising one into the other here would mean the
/// registered string and the served string could differ. Refusing instead is
/// the decision ADR-0005 already makes for `redirect_uri`.
fn is_canonical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > MAX_HOST_LENGTH {
        return false;
    }
    // `split` yields an empty label for a leading, trailing or doubled dot, and
    // an empty label is rejected below — so `example.test.` and `.example` are
    // both out without a special case.
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LENGTH
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

/// Whether `port` is a decimal port number in the one spelling a canonical
/// origin uses.
///
/// No leading zeros, because `https://rp.example:0443` and
/// `https://rp.example:443` would be one origin to a browser and two strings
/// here — and a value that reads as one port to a parser and another to a
/// comparison is the shape of every redirect-URI confusion bug.
fn is_canonical_port(port: &str) -> bool {
    if port.is_empty() || port.len() > 5 || port.starts_with('0') {
        return false;
    }
    port.parse::<u32>()
        .is_ok_and(|number| (1..=65535).contains(&number))
}

/// Why a string is not an origin this policy can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidOrigin {
    /// Longer than any registered callback's origin can be.
    #[error("an origin is at most 255 characters")]
    TooLong,
    /// Not `scheme://…` at all.
    #[error("an origin is a scheme, a host and an optional port, and nothing else")]
    NotAnOrigin,
    /// Not `https`, and not the loopback `http` exception.
    #[error("only https, or http on the 127.0.0.1 loopback callback, can receive a form post")]
    Scheme,
    /// Not a canonical, already-punycoded DNS name or IPv4 literal.
    #[error("the host is not a lower-case DNS name or IPv4 literal")]
    Host,
    /// Not a port number, or not written the way a canonical origin writes one.
    #[error("the port is not 1-65535 written without leading zeros")]
    Port,
}

/// The policy a document is served under.
///
/// One value with one variable part, rather than a string built at each call
/// site: a policy assembled per page is a policy that differs per page, and the
/// difference is never noticed until the page that got the weak one is the
/// consent screen.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The client origin a `form_post` response submits to, if this is one.
    form_action: Option<FormActionOrigin>,
}

impl Policy {
    /// The policy every page gets unless it asks for the one variation below.
    #[must_use]
    pub const fn strict() -> Self {
        Self { form_action: None }
    }

    /// Adds one origin to `form-action`, for a `response_mode=form_post` page.
    ///
    /// Additive and single-valued on purpose. `form-action` is what stops an
    /// injected form in a login page from posting the password somewhere else,
    /// so the seam `ast-gxh.5` needs is "this one page also submits to this one
    /// registered callback", not "a page may choose its own `form-action`".
    #[must_use]
    pub fn with_form_post_to(mut self, origin: FormActionOrigin) -> Self {
        self.form_action = Some(origin);
        self
    }

    /// Renders the `Content-Security-Policy` header value for one response.
    ///
    /// Taking the nonce as an argument rather than storing it is what makes a
    /// stale nonce hard to write: the value comes from the middleware that is
    /// about to set this header, on the way out of the same request.
    #[must_use]
    pub fn header_value(&self, nonce: &Nonce) -> String {
        let nonce = nonce.as_str();
        // `FormActionOrigin` cannot hold a `;`, a quote or a space, so this
        // interpolation cannot add a directive or a source expression.
        let form_post_target = match &self.form_action {
            Some(origin) => format!(" {}", origin.as_str()),
            None => String::new(),
        };

        format!(
            "default-src 'none'; \
             script-src 'nonce-{nonce}' 'strict-dynamic'; \
             style-src 'nonce-{nonce}'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self'; \
             form-action 'self'{form_post_target}; \
             frame-ancestors 'none'; \
             base-uri 'none'; \
             object-src 'none'"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// How many `;` separate the directives. The policy has ten directives, so
    /// nine — and a rendered policy with a tenth `;` has grown a directive from
    /// somewhere, which is the only thing an origin could ever do to it.
    const SEPARATORS: usize = 9;

    fn fixed_nonce(value: &str) -> Nonce {
        Nonce(value.to_owned())
    }

    /// The reviewed policy, written out once. A change to the directive set has
    /// to edit this line, so that the diff is what gets reviewed.
    #[test]
    fn the_rendered_policy_is_the_one_that_was_reviewed() {
        assert_eq!(
            Policy::strict().header_value(&fixed_nonce("Ab3-_0")),
            "default-src 'none'; \
             script-src 'nonce-Ab3-_0' 'strict-dynamic'; \
             style-src 'nonce-Ab3-_0'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self'; \
             form-action 'self'; \
             frame-ancestors 'none'; \
             base-uri 'none'; \
             object-src 'none'"
        );
    }

    #[test]
    fn a_form_post_page_names_exactly_the_one_extra_origin() {
        let origin = FormActionOrigin::parse("https://rp.example").expect("an origin");
        let rendered = Policy::strict()
            .with_form_post_to(origin)
            .header_value(&fixed_nonce("n"));
        assert!(rendered.contains("form-action 'self' https://rp.example;"));
        // ...and nothing else moved.
        assert!(rendered.contains("frame-ancestors 'none'"));
        assert!(rendered.contains("base-uri 'none'"));
    }

    /// A host is not a keyword, however it is spelled.
    ///
    /// CSP Level 3 §2.3.1 writes every dangerous source quoted —
    /// `'unsafe-inline'`, `'unsafe-eval'`, `'unsafe-hashes'` — and never
    /// writes a host-source that way. So `unsafe-` as a run of host-chars is
    /// an ordinary domain somebody can register and register as a
    /// `redirect_uri`, and the thing that keeps a keyword out is the quoting,
    /// not the letters. A check on the unquoted substring refuses a legitimate
    /// client for a resemblance (`ast-83p.14`).
    #[test]
    fn a_host_whose_name_contains_unsafe_is_still_only_a_host() {
        let origin = FormActionOrigin::parse("https://unsafe-eval.example").expect("an origin");
        let rendered = Policy::strict()
            .with_form_post_to(origin)
            .header_value(&fixed_nonce("n"));

        assert!(rendered.contains("form-action 'self' https://unsafe-eval.example;"));
        // The keyword is the quoted spelling, and it is not here.
        assert!(
            !rendered.contains("'unsafe-"),
            "a host introduced a quoted keyword: {rendered}"
        );
        assert_eq!(
            rendered.matches('\'').count(),
            Policy::strict()
                .header_value(&fixed_nonce("n"))
                .matches('\'')
                .count(),
            "widening the policy changed how many quoted sources it names"
        );
    }

    /// The acceptance criterion, over every policy this type can produce.
    #[test]
    fn unsafe_keywords_appear_in_no_policy() {
        let origin = FormActionOrigin::parse("https://rp.example:8443").expect("an origin");
        for policy in [Policy::strict(), Policy::strict().with_form_post_to(origin)] {
            let rendered = policy.header_value(&Nonce::generate());
            for forbidden in [
                "unsafe-inline",
                "unsafe-eval",
                "unsafe-hashes",
                "wasm-unsafe-eval",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "the policy permits {forbidden}: {rendered}"
                );
            }
            // A wildcard or a bare scheme source would let script back in the
            // front door that `'strict-dynamic'` closed at the back.
            assert!(!rendered.contains('*'), "wildcard source: {rendered}");
            assert!(!rendered.contains("script-src 'self'"));
        }
    }

    /// CSP Level 3 §7.1: the whole policy rests on the nonce, so it has to be
    /// unique per response and unguessable.
    #[test]
    fn a_nonce_is_128_bits_of_base64url_and_never_repeats() {
        const DRAWS: usize = 1000;
        let nonces: HashSet<String> = (0..DRAWS)
            .map(|_| Nonce::generate().as_str().to_owned())
            .collect();
        assert_eq!(nonces.len(), DRAWS, "a nonce repeated");
        for nonce in &nonces {
            assert_eq!(nonce.len(), 22, "128 bits is 22 base64 symbols");
            assert!(
                nonce
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "nonce left the CSP base64-value grammar: {nonce}"
            );
        }
    }

    #[test]
    fn the_nonce_reaches_both_the_policy_and_the_tag_it_allows() {
        let nonce = Nonce::generate();
        let policy = Policy::strict().header_value(&nonce);
        assert!(policy.contains(&format!("script-src 'nonce-{}'", nonce.as_str())));
        assert!(policy.contains(&format!("style-src 'nonce-{}'", nonce.as_str())));
        assert_eq!(nonce.attribute(), format!("nonce=\"{}\"", nonce.as_str()));
    }

    #[test]
    fn a_serialized_origin_is_accepted_unchanged() {
        for origin in [
            "https://rp.example",
            "https://rp.example:8443",
            "https://sub.domain.rp-2.example",
            "https://203.0.113.7",
            "https://rp.example:65535",
            // RFC 8252 §7.3 loopback callback.
            "http://127.0.0.1",
            "http://127.0.0.1:51004",
        ] {
            let parsed = FormActionOrigin::parse(origin).expect(origin);
            assert_eq!(parsed.as_str(), origin, "the origin was rewritten");
        }
    }

    /// The cases that matter are not the malformed ones; they are the ones that
    /// would still render into a header and mean something else there.
    #[test]
    fn an_origin_that_could_change_the_policy_is_refused() {
        for (hostile, why) in [
            ("https://rp.example; script-src *", "adds a directive"),
            ("https://rp.example 'unsafe-inline'", "adds a source"),
            (
                "https://rp.example\r\nX-Frame-Options: ALLOWALL",
                "splits the response",
            ),
            ("https://rp.example\n", "trailing newline"),
            ("https://*.example", "wildcard host"),
            ("https://rp.example/callback", "carries a path"),
            ("https://rp.example/", "carries an empty path"),
            ("https://user:pw@rp.example", "carries userinfo"),
            ("https://rp.example?a=b", "carries a query"),
            ("https://rp.example#f", "carries a fragment"),
            ("http://rp.example", "not https and not loopback"),
            ("http://localhost:8080", "a name, not the loopback literal"),
            ("javascript://rp.example", "not a fetch scheme"),
            ("data://rp.example", "not a fetch scheme"),
            (
                "https://[::1]:8443",
                "an IPv6 literal is not a CSP host-source",
            ),
            ("https://RP.example", "not canonical"),
            ("https://rp.example.", "trailing dot"),
            ("https://rp..example", "empty label"),
            ("https://-rp.example", "label starts with a hyphen"),
            ("https://rp_1.example", "underscore is not a host-char"),
            ("https://rp.example:0", "port zero"),
            ("https://rp.example:0443", "leading zero in the port"),
            ("https://rp.example:65536", "port out of range"),
            ("https://rp.example:https", "a port that is not a number"),
            ("https://", "no host"),
            ("rp.example", "no scheme"),
            ("", "empty"),
        ] {
            assert!(
                FormActionOrigin::parse(hostile).is_err(),
                "accepted {hostile:?} ({why})"
            );
        }

        let long = format!("https://{}.example", "a".repeat(MAX_ORIGIN_LENGTH));
        assert_eq!(
            FormActionOrigin::parse(&long),
            Err(InvalidOrigin::TooLong),
            "accepted an unbounded origin"
        );
    }

    /// The property the fuzz target checks over arbitrary input, pinned here
    /// for the inputs that got there first.
    #[test]
    fn an_accepted_origin_cannot_add_a_directive() {
        for origin in ["https://rp.example", "https://127.0.0.1:8443"] {
            let origin = FormActionOrigin::parse(origin).expect("an origin");
            let rendered = Policy::strict()
                .with_form_post_to(origin)
                .header_value(&Nonce::generate());
            assert_eq!(rendered.matches(';').count(), SEPARATORS);
            assert!(rendered.is_ascii());
        }
        assert_eq!(
            Policy::strict()
                .header_value(&Nonce::generate())
                .matches(';')
                .count(),
            SEPARATORS
        );
    }
}
