//! The configuration reference, generated from the configuration schema.
//!
//! `docs/configuration.md` is written by this module, not by a person:
//!
//! ```text
//! cargo run --quiet --bin asterius -- --config-reference > docs/configuration.md
//! ```
//!
//! A reference kept by hand is wrong from the first key somebody adds, and
//! nobody notices until an operator sets a security flag that does nothing. So
//! three things here come out of the code rather than out of prose:
//!
//! * **Which keys exist.** [`crate::config::declared_keys`] reads them out of
//!   the deserializers themselves. A key documented here that the file does not
//!   accept, or a key the file accepts that is not documented here, fails this
//!   module's `every_key_is_documented` test.
//! * **What the defaults are.** The default column is formatted from the same
//!   constants the validator applies, so a default cannot be changed in one
//!   place and described in the other.
//! * **Which flags exist.** The `[features]` table is generated from
//!   [`Feature::ALL`], the registry that discovery and `/readyz` also read.
//!
//! What stays prose is what only a person can say: why a key exists and what
//! goes wrong if it is set carelessly. That is the part a reference is for.

use crate::config::{
    DEFAULT_ADMIN_TENANT, DEFAULT_ADMIN_USERNAME, DEFAULT_BIND, DEFAULT_BODY_LIMIT,
    DEFAULT_LIMIT_CLIENT_CONFIGURATION_PER_ADDRESS, DEFAULT_LIMIT_PAR_PER_ADDRESS,
    DEFAULT_LIMIT_PAR_PER_CLIENT, DEFAULT_LIMIT_REGISTRATION_PER_ADDRESS,
    DEFAULT_LIMIT_TOKEN_PER_ADDRESS, DEFAULT_LIMIT_TOKEN_PER_CLIENT,
    DEFAULT_LIMIT_USERINFO_PER_ADDRESS, DEFAULT_LIMIT_WINDOW_SECONDS,
    DEFAULT_LOGIN_MAX_PER_ACCOUNT, DEFAULT_LOGIN_MAX_PER_ADDRESS, DEFAULT_LOGIN_WINDOW_SECONDS,
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MODE, DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_TRUSTED_PROXIES, MIN_LIMIT_WINDOW_SECONDS, MIN_LOGIN_WINDOW_SECONDS, ROOT_TABLE,
    TransportMode,
};
use crate::http::register::MIN_INITIAL_ACCESS_TOKEN_LEN;
use crate::observability::LogFormat;
use asterius_domain::entities::tenant::{
    DEFAULT_REFRESH_ABSOLUTE_LIFETIME, DEFAULT_REFRESH_IDLE_LIFETIME,
};
use asterius_domain::{Capabilities, Feature};
use std::fmt::Write as _;

/// One documented key.
#[derive(Debug)]
pub struct Key {
    /// The key as it is written in its table, e.g. `bind`.
    pub name: String,
    /// The value's shape, in the words an operator writing TOML would use.
    pub kind: &'static str,
    /// What happens when the key is absent.
    pub default: String,
    /// Why the key exists and what a careless value costs.
    pub notes: String,
}

/// One documented table.
#[derive(Debug)]
pub struct Section {
    /// The table's path, or [`ROOT_TABLE`] for the top level.
    pub table: &'static str,
    /// The heading it appears under.
    pub heading: &'static str,
    /// What the table is for.
    pub blurb: &'static str,
    /// Its keys, in the order they should be read.
    pub keys: Vec<Key>,
}

impl Section {
    /// The table this one is nested in, if any.
    #[must_use]
    pub fn parent(&self) -> Option<&'static str> {
        if self.table == ROOT_TABLE {
            None
        } else {
            Some(
                self.table
                    .rsplit_once('.')
                    .map_or(ROOT_TABLE, |(head, _)| head),
            )
        }
    }

    /// The key that introduces this table in its parent, e.g. `tls`.
    #[must_use]
    pub fn key_in_parent(&self) -> &'static str {
        self.table
            .rsplit_once('.')
            .map_or(self.table, |(_, tail)| tail)
    }
}

fn key(name: &str, kind: &'static str, default: String, notes: &str) -> Key {
    Key {
        name: name.to_owned(),
        kind,
        default,
        notes: notes.to_owned(),
    }
}

/// Spelled once so "required" reads the same in every row.
const REQUIRED: &str = "**required**";

/// How the default log format is written in the file.
const fn default_log_format() -> &'static str {
    // Matched rather than `Debug`-printed: the file takes the serde name, and
    // a rename would otherwise silently document a key that does not parse.
    match LogFormat::Text {
        LogFormat::Text => "text",
        LogFormat::Json => "json",
    }
}

/// How the default transport mode is written in the file.
const fn default_mode() -> &'static str {
    match DEFAULT_MODE {
        TransportMode::TerminateTls => "terminate_tls",
        TransportMode::BehindProxy => "behind_proxy",
    }
}

/// Every documented table, in the order the reference presents them.
#[must_use]
pub fn sections() -> Vec<Section> {
    vec![
        root(),
        server(),
        server_tls(),
        server_proxy(),
        database(),
        keys_table(),
        features_section(),
        registration(),
        login(),
        limits(),
        tenant(),
        tenant_refresh(),
        admin(),
    ]
}

/// Keys that belong to the process rather than to any one table.
fn root() -> Section {
    Section {
        table: ROOT_TABLE,
        heading: "Top level",
        blurb: "Keys that belong to the process rather than to any one part of it.",
        keys: vec![key(
            "log_format",
            "`\"text\"` or `\"json\"`",
            format!("`\"{}\"`", default_log_format()),
            "`json` for a log pipeline, `text` for a terminal. Either way every field \
             passes through the redaction formatter first, so a credential cannot reach \
             an appender (RFC 9700 §4.2-4.3).",
        )],
    }
}

/// `[server]`: where the process listens and how TLS reaches it.
fn server() -> Section {
    Section {
        table: "server",
        heading: "`[server]` — listener and transport",
        blurb: "Where the process listens and how TLS reaches it.",
        keys: vec![
            key(
                "bind",
                "socket address",
                format!("`\"{DEFAULT_BIND}\"`"),
                "Deliberately not `:8443`, which `tailscale serve` binds on a node's \
                 Tailscale addresses.",
            ),
            key(
                "mode",
                "`\"terminate_tls\"` or `\"behind_proxy\"`",
                format!("`\"{}\"`", default_mode()),
                "`terminate_tls` requires `[server.tls]` and rejects `[server.proxy]`; \
                 `behind_proxy` is the mirror image. A deployment that configures \
                 certificates while running behind a proxy usually believes it is doing \
                 TLS and is not.",
            ),
            key(
                "request_body_limit_bytes",
                "integer",
                format!("`{DEFAULT_BODY_LIMIT}`"),
                "FAPI 2.0 request bodies are small — a PAR request, a token request, a \
                 registration document — so anything larger is a mistake or an attempt. \
                 Over the limit: 413.",
            ),
            key(
                "request_timeout_seconds",
                "integer",
                format!("`{DEFAULT_REQUEST_TIMEOUT_SECONDS}`"),
                "Long enough for a slow client on a bad link, short enough that holding \
                 a connection open is not a denial-of-service primitive.",
            ),
        ],
    }
}

/// `[server.tls]`: this process's own certificate.
fn server_tls() -> Section {
    Section {
        table: "server.tls",
        heading: "`[server.tls]` — this process's certificate",
        blurb: "Required when `server.mode = \"terminate_tls\"`, and rejected otherwise. \
                TLS 1.2 and 1.3 only, with the BCP 195 cipher suites FAPI 2.0 SP \
                §5.2.1-5.2.2 permits. There is no knob to widen either set.",
        keys: vec![
            key(
                "certificate",
                "path",
                format!("{REQUIRED} in `terminate_tls` mode"),
                "PEM certificate chain, leaf first.",
            ),
            key(
                "private_key",
                "path",
                format!("{REQUIRED} in `terminate_tls` mode"),
                "PEM private key. Mounted read-only and never baked into an image; see \
                 \"Secret sources\" below.",
            ),
        ],
    }
}

/// `[server.proxy]`: which peers may speak for a client.
fn server_proxy() -> Section {
    Section {
        table: "server.proxy",
        heading: "`[server.proxy]` — who may speak for a client",
        blurb: "Only meaningful when `server.mode = \"behind_proxy\"`, and rejected \
                otherwise.",
        keys: vec![key(
            "trusted_cidrs",
            "array of CIDR blocks",
            format!("`{DEFAULT_TRUSTED_PROXIES:?}`"),
            "`X-Forwarded-For` and `Forwarded` are assertions any client can make, so \
             they are believed only when the immediate peer is listed here. The resolved \
             address feeds rate limiting, login abuse protection and the audit trail: a \
             spoofable address means a spoofable rate-limit bucket and an audit record \
             naming the wrong person.",
        )],
    }
}

/// `[database]`: the one PostgreSQL instance.
fn database() -> Section {
    Section {
        table: "database",
        heading: "`[database]` — PostgreSQL",
        blurb: "One PostgreSQL instance holds everything. There is no second store to \
                keep consistent.",
        keys: vec![
            key(
                "url",
                "connection URL (**secret**)",
                REQUIRED.to_owned(),
                "Contains a password, so it is held redacted and prints as `[REDACTED]` \
                 wherever the configuration is logged. Prefer supplying it through \
                 `ASTERIUS__DATABASE__URL` from a secret store over writing it in the \
                 file.",
            ),
            key(
                "max_connections",
                "integer",
                format!("`{DEFAULT_MAX_CONNECTIONS}`"),
                "Per process. Multiply by the replica count before comparing it with the \
                 server's `max_connections`.",
            ),
        ],
    }
}

/// `[keys]`: where the key-encryption key comes from.
fn keys_table() -> Section {
    Section {
        table: "keys",
        heading: "`[keys]` — the key-encryption key",
        blurb: "**Required, with no default.** Signing keys are encrypted at rest under \
                this key, and one generated at each boot could not open yesterday's rows \
                — the failure would look like corruption rather than like configuration. \
                Set exactly one of the two keys below; setting both is an error, because \
                the server would otherwise choose between them silently. The value is 32 \
                bytes, base64: `head -c 32 /dev/urandom | base64`.",
        keys: vec![
            key(
                "kek_file",
                "path (**points at a secret**)",
                format!("{REQUIRED}, unless `kek_env` is set"),
                "The production shape: the orchestrator mounts the file read-only and it \
                 is never in the image.",
            ),
            key(
                "kek_env",
                "variable name (**names a secret**)",
                format!("{REQUIRED}, unless `kek_file` is set"),
                "Convenient in a container and readable through `/proc/self/environ`, so \
                 the file is preferred.",
            ),
        ],
    }
}

/// `[features]`: the optional capabilities, from the flag registry.
fn features_section() -> Section {
    Section {
        table: "features",
        heading: "`[features]` — optional capabilities",
        blurb: "Everything is off unless switched on here, and what is switched on is \
                exactly what appears in the discovery metadata and on `/readyz`. There is \
                no flag that weakens the FAPI 2.0 baseline (ADR-0002) and no `rs256` \
                (ADR-0003).",
        keys: features(),
    }
}

/// `[registration]`: who may register a client dynamically.
fn registration() -> Section {
    Section {
        table: "registration",
        heading: "`[registration]` — dynamic client registration",
        blurb: "`POST /register` (RFC 7591 §3). Omit the table entirely and the endpoint \
                registers nobody. That is a deliberate departure from RFC 7591 §3's \
                SHOULD: the SHOULD exists so clients can interoperate with servers nobody \
                has agreed with in advance, and a FAPI deployment's clients are \
                counterparties rather than strangers. The cost of the other default is an \
                internet-writable row in `clients`.",
        keys: vec![
            key(
                "mode",
                "`\"closed\"`, `\"initial_access_token\"` or `\"open\"`",
                format!("{REQUIRED} when `[registration]` is present"),
                "Never inferred from whether tokens are present: deleting the last token \
                 would otherwise turn a gated endpoint into an open one.",
            ),
            key(
                "initial_access_tokens",
                "array of strings (**secret**)",
                format!("{REQUIRED} under `initial_access_token`, rejected otherwise"),
                &format!(
                    "Hashed at startup, so the running process holds only digests. Each \
                     must be at least {MIN_INITIAL_ACCESS_TOKEN_LEN} characters, which is \
                     the 128 bits FAPI 2.0 SP §5.4.1 requires of a credential no end user \
                     handles."
                ),
            ),
        ],
    }
}

/// `[login]`: what bounds online guessing.
fn login() -> Section {
    Section {
        table: "login",
        heading: "`[login]` — abuse protection at sign-in",
        blurb: "Failed sign-ins are counted per client address and per typed \
                identifier, in fixed windows held in the database so that every replica \
                sees the same counter (NIST SP 800-63B §5.2.2). Both limits apply and \
                they stop different attacks: the per-account one bounds the guessing of \
                one password, the per-address one bounds a sweep across many accounts. \
                The identifier is hashed before it is counted and the bucket exists \
                whether the account does or not, so a locked-out identifier and one that \
                was never registered are the same observable.",
        keys: vec![
            key(
                "failure_window_seconds",
                "integer seconds",
                DEFAULT_LOGIN_WINDOW_SECONDS.to_string(),
                &format!(
                    "How long failures are remembered. At least \
                     {MIN_LOGIN_WINDOW_SECONDS}: a window shorter than that resets \
                     before an attacker's attempts add up, which is a limit in name only."
                ),
            ),
            key(
                "max_failures_per_account",
                "integer",
                DEFAULT_LOGIN_MAX_PER_ACCOUNT.to_string(),
                "Failures tolerated per window against one typed identifier before \
                 sign-ins are refused with a retry hint. Raising it buys an attacker \
                 guesses; lowering it makes a targeted lockout of one user cheaper to \
                 cause.",
            ),
            key(
                "max_failures_per_address",
                "integer",
                DEFAULT_LOGIN_MAX_PER_ADDRESS.to_string(),
                "Failures tolerated per window from one client address. Higher than the \
                 per-account limit because one address is legitimately many people — an \
                 office, a carrier's NAT — and because behind a proxy it is only as \
                 trustworthy as `[server.proxy] trusted_cidrs` makes it.",
            ),
        ],
    }
}

/// `[limits]`: what each protocol endpoint permits per window.
fn limits() -> Section {
    Section {
        table: "limits",
        heading: "`[limits]` — abuse protection at the protocol endpoints",
        blurb: "Requests — not failures — are counted per endpoint, in the same \
                fixed windows and the same database table the sign-in limiter uses, so \
                every replica sees one counter. A **successful** request from a client \
                that authenticated is charged to that client; everything else is \
                charged to the address it came from. That is what keeps one busy \
                relying party from spending the budget of everyone behind the same \
                NAT, and what stops a caller from exhausting a competitor's budget by \
                naming their `client_id` in a request that fails. Exceeding a limit is \
                answered with 429 and `Retry-After`, counted in \
                `asterius_endpoint_throttled_total`, and written to the audit trail \
                once per window rather than once per request. `/authorize` and the \
                interaction pages are not here: the sign-in behind them is bounded by \
                `[login]`, and a second counter over the same requests would halve a \
                number set once.",
        keys: vec![
            key(
                "window_seconds",
                "integer seconds",
                DEFAULT_LIMIT_WINDOW_SECONDS.to_string(),
                &format!(
                    "How long requests are counted for, for every endpoint below. At \
                     least {MIN_LIMIT_WINDOW_SECONDS}. Shorter than `[login]`'s window \
                     on purpose: these limits bound load rather than guessing, and a \
                     caller refused for a quarter of an hour over a five-second burst \
                     is an outage rather than a defence."
                ),
            ),
            key(
                "registration_per_address",
                "integer",
                DEFAULT_LIMIT_REGISTRATION_PER_ADDRESS.to_string(),
                "Requests per window to `POST /register` (RFC 7591) from one address. \
                 The tightest limit here: with `[registration] mode = \"open\"` this is \
                 the one endpoint that both needs no credential and creates a row per \
                 accepted request. There is no per-client limit, because registration \
                 is where a client comes from.",
            ),
            key(
                "client_configuration_per_address",
                "integer",
                DEFAULT_LIMIT_CLIENT_CONFIGURATION_PER_ADDRESS.to_string(),
                "Requests per window to the RFC 7592 configuration endpoint from one \
                 address. What it bounds is a caller trying registration access tokens \
                 against a client id it guessed; the bucket is the address and never \
                 the id in the path, which anybody can write.",
            ),
            key(
                "par_per_address",
                "integer",
                DEFAULT_LIMIT_PAR_PER_ADDRESS.to_string(),
                "Requests per window to `POST /par` (RFC 9126) from one address, for \
                 requests that do not end in a successful push. Each accepted request \
                 stores a row, so an abusive caller here fills a table.",
            ),
            key(
                "par_per_client",
                "integer",
                DEFAULT_LIMIT_PAR_PER_CLIENT.to_string(),
                "Successful pushes per window by one authenticated client. An order of \
                 magnitude above the address limit, because one relying party is \
                 legitimately many users starting authorization at once.",
            ),
            key(
                "token_per_address",
                "integer",
                DEFAULT_LIMIT_TOKEN_PER_ADDRESS.to_string(),
                "Requests per window to `POST /token` from one address, for requests \
                 that do not end in a token. Every attempt costs a signature \
                 verification, and replaying an authorization code revokes the grant it \
                 belongs to, so abuse here has a side effect as well as a cost.",
            ),
            key(
                "token_per_client",
                "integer",
                DEFAULT_LIMIT_TOKEN_PER_CLIENT.to_string(),
                "Successful token responses per window for one authenticated client. \
                 The busiest endpoint a working deployment has — every authorization \
                 and every refresh passes through it — so this is the number to raise \
                 first when a large client is refused.",
            ),
            key(
                "userinfo_per_address",
                "integer",
                DEFAULT_LIMIT_USERINFO_PER_ADDRESS.to_string(),
                "Requests per window to UserInfo from one address. The most generous \
                 of the five: its callers are resource servers rather than browsers, so \
                 one address is legitimately a fleet making a request per API call. \
                 There is no per-client limit, because the caller presents an access \
                 token and reading a client out of it before verifying it would be \
                 trusting a string the caller wrote.",
            ),
        ],
    }
}

/// `[[tenant]]`: the tenants that exist at boot.
fn tenant() -> Section {
    Section {
        table: "tenant",
        heading: "`[[tenant]]` — one table per tenant",
        blurb: "A tenant is an issuer. This array is the source of truth for which \
                tenants exist at boot; the admin API adds more at runtime. The upsert is \
                idempotent, so a restart re-asserts the declared shape.",
        keys: vec![
            key(
                "id",
                "string",
                REQUIRED.to_owned(),
                "Becomes a path segment in the issuer and in every request URL, so it is \
                 validated rather than trusted.",
            ),
            key(
                "issuer",
                "https URL, no query, no fragment",
                REQUIRED.to_owned(),
                "Normalised once at startup — scheme and host lower-cased, a default \
                 `:443` dropped, a trailing slash removed — and the canonical form is \
                 what appears in every `iss` claim (RFC 8414 §2, OIDC Discovery §3).",
            ),
            key(
                "default_resource",
                "https URL, no fragment",
                "the tenant's `issuer`".to_owned(),
                "The `aud` an access token carries when the authorization request named \
                 no `resource` of its own (RFC 8707 §2, RFC 9068 §3). The default means \
                 \"a token for this server's own protected resources\"; a deployment \
                 fronting a separate API names that API here.",
            ),
        ],
    }
}

/// `[tenant.refresh]`: what a tenant does with refresh tokens.
fn tenant_refresh() -> Section {
    Section {
        table: "tenant.refresh",
        heading: "`[tenant.refresh]` — refresh tokens",
        blurb: "Omit the table and this tenant gets FAPI 2.0 SP's position: no rotation, a \
                refresh token that only works with the DPoP key it was issued to, and the \
                lifetimes below. The table is per tenant because how long an authorization \
                may be acted on without the user present is a question two tenants of one \
                deployment routinely answer differently.",
        keys: vec![
            key(
                "absolute_lifetime_seconds",
                "positive integer",
                format!(
                    "`{}` (30 days)",
                    DEFAULT_REFRESH_ABSOLUTE_LIFETIME.whole_seconds()
                ),
                "How long a refresh token may live at all. It never moves: using the token \
                 does not push it out, which is what makes it the one deadline an attacker \
                 holding the token cannot extend. Past it the client sends the user through \
                 authorization again.",
            ),
            key(
                "idle_lifetime_seconds",
                "positive integer, or `0` to disable",
                format!(
                    "`{}` (14 days)",
                    DEFAULT_REFRESH_IDLE_LIFETIME.whole_seconds()
                ),
                "How long the token may sit unused. Every successful refresh pushes it out, \
                 so it answers \"is this integration still in use\" rather than \"is this \
                 authorization still fresh\". Capped at `absolute_lifetime_seconds`, because \
                 a longer value is not a stricter setting but one with no effect. `0` \
                 switches the idle clock off; the absolute deadline still runs.",
            ),
            key(
                "bind_to_dpop_key",
                "boolean",
                "`false`".to_owned(),
                "Whether the refresh token may only be presented with the DPoP key it was \
                 issued to. Off by default because that is RFC 9449 §5: a refresh token \
                 issued to a *confidential* client is not bound to the proof key, being \
                 sender-constrained by client authentication already, and this server \
                 registers no public clients. A client may therefore roll its DPoP key and \
                 keep its authorizations, and the new access token is bound to the key it \
                 proves. Turning it on is a local hardening — a refresh token copied out of \
                 a client's store is then useless without that client's DPoP private key as \
                 well — and it breaks any client that rolls that key.",
            ),
            key(
                "rotation",
                "`\"none\"` or `\"migration\"`",
                "`\"none\"`".to_owned(),
                "FAPI 2.0 SP §5.3.2.1 item 9: an authorization server \"shall not use \
                 refresh token rotation except in extraordinary circumstances\". `\"none\"` \
                 returns the same token unchanged. `\"migration\"` is Note 1's exception and \
                 exists for one purpose — moving off a server that rotated, where clients in \
                 the field discard a refresh token they did not just receive. It is not a \
                 hardening measure, it is a compatibility shim, and it is meant to be \
                 switched off again.",
            ),
            key(
                "rotation_grace_seconds",
                "positive integer, at most 3600",
                "**required** with `rotation = \"migration\"`, and refused otherwise".to_owned(),
                "How long the superseded token stays acceptable, so a client that crashed \
                 between receiving the response and storing it can retry. It is a window in \
                 which two refresh tokens are live for one grant, which is the state \
                 rotation exists to eliminate — hence the hour ceiling and hence the \
                 refusal to accept the key at all under `rotation = \"none\"`, where it \
                 would describe something the server does not do.",
            ),
        ],
    }
}

/// `[admin]`: the deployment admin seeded at boot.
fn admin() -> Section {
    Section {
        table: "admin",
        heading: "`[admin]` — the deployment admin",
        blurb: "Omit the table and nothing is seeded. A deployment admin is a user of a \
                *reserved tenant* holding a deployment-scoped role (ADR-0010): the tenant \
                is created if it is absent, marked reserved, and cannot be deleted \
                afterwards — the cascade from `tenants` is what would otherwise remove \
                every admin in one statement. The seed runs on every boot and is \
                idempotent; it finishes by verifying the configured password through the \
                ordinary login verifier, and the server refuses to start if the account \
                it just asserted could not sign in.",
        keys: vec![
            key(
                "tenant",
                "string",
                format!("`\"{DEFAULT_ADMIN_TENANT}\"`"),
                "The reserved tenant's id. It must not also be declared as a \
                 `[[tenant]]`: the seed is what creates and marks it. Discoverable by \
                 anyone who can list tenants, deliberately — an admin surface that hides \
                 where its authority lives is harder to audit, not safer.",
            ),
            key(
                "issuer",
                "https URL, no query, no fragment",
                format!("{REQUIRED} when `[admin]` is present"),
                "The reserved tenant is a real tenant and needs an issuer like any \
                 other, with the same normalisation and the same host check. Its login \
                 surface therefore deserves the same scrutiny as any tenant's.",
            ),
            key(
                "username",
                "string",
                format!("`\"{DEFAULT_ADMIN_USERNAME}\"`"),
                "The login identifier, unique within the reserved tenant.",
            ),
            key(
                "password_file",
                "path (**points at a secret**)",
                format!("{REQUIRED}, unless `password_env` is set"),
                "The production shape: a file the orchestrator mounts read-only. Leading \
                 and trailing whitespace is stripped, so a trailing newline is not part \
                 of the password.",
            ),
            key(
                "password_env",
                "variable name (**names a secret**)",
                format!("{REQUIRED}, unless `password_file` is set"),
                "The named variable, injected by the orchestrator. Readable through \
                 `/proc/self/environ`, so the file is preferred. There is no key that \
                 takes the password itself: a credential written in the file is a \
                 credential in version control and in every copy of the image.",
            ),
        ],
    }
}

/// The `[features]` rows, one per flag in the registry.
///
/// Generated from [`Feature::ALL`] so that a flag added to the registry appears
/// here without anybody remembering to add it, which is the failure mode this
/// whole module exists to prevent.
fn features() -> Vec<Key> {
    let defaults = Capabilities::default();
    Feature::ALL
        .into_iter()
        .map(|feature| {
            Key {
                name: feature.as_str().to_owned(),
                kind: "boolean",
                default: format!("`{}`", defaults.is_enabled(feature)),
                notes: match feature {
                    Feature::Mtls => {
                        "mTLS client authentication and certificate-bound tokens (RFC 8705)."
                    }
                    Feature::GrantManagement => {
                        "Grant Management for OAuth 2.0 (Implementer's Draft)."
                    }
                    Feature::Ciba => "CIBA Core 1.0 backchannel authentication, poll and ping.",
                    Feature::DeviceFlow => "Device Authorization Grant (RFC 8628).",
                    Feature::TokenExchange => "Token Exchange (RFC 8693) with delegation chains.",
                    Feature::Ssf => "Shared Signals Framework transmitter and CAEP/RISC events.",
                    Feature::Authzen => "AuthZEN Authorization API 1.0 policy decision point.",
                    Feature::DpopNonce => "Server-issued DPoP nonces (RFC 9449 §8).",
                    // `Feature` is `#[non_exhaustive]`: a flag added without a
                    // sentence here still gets documented, and the row says so
                    // loudly enough that somebody fixes it.
                    _ => "Undocumented flag: add a description in `config_reference.rs`.",
                }
                .to_owned(),
            }
        })
        .collect()
}

/// The command that regenerates the reference, named in the file itself.
pub const REGENERATE_COMMAND: &str =
    "cargo run --quiet --bin asterius -- --config-reference > docs/configuration.md";

/// Renders the whole reference as Markdown.
///
/// Deterministic: the same binary always produces the same bytes, which is what
/// lets a test compare it against the file checked into `docs/`.
#[must_use]
pub fn render() -> String {
    let mut out = String::with_capacity(8 * 1024);

    let _ = writeln!(out, "# Configuration reference\n");
    let _ = writeln!(
        out,
        "<!-- Generated file. Do not edit by hand: run `{REGENERATE_COMMAND}`. -->\n"
    );
    let _ = out.write_str(PREAMBLE);

    for section in sections() {
        let _ = writeln!(out, "\n## {}\n", section.heading);
        let _ = writeln!(out, "{}\n", section.blurb);
        let _ = writeln!(out, "| Key | Type | Default | Notes |");
        let _ = writeln!(out, "| --- | --- | --- | --- |");
        for key in &section.keys {
            let path = if section.table == ROOT_TABLE {
                key.name.clone()
            } else {
                format!("{}.{}", section.table, key.name)
            };
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                path, key.kind, key.default, key.notes
            );
        }
    }

    let _ = out.write_str(SECRETS);
    out
}

/// The part of the document that describes the file as a whole.
const PREAMBLE: &str = "\
Asterius reads one TOML file, named by `--config` or `ASTERIUS_CONFIG` and
defaulting to `asterius.toml` in the working directory.

**An unknown key is a startup error, not a warning.** A typo in a security flag
must never be silently ignored, so every table rejects keys it does not know and
the error names the full key path. Validation problems are accumulated and
reported together: fixing a configuration should take one round trip, not one
restart per mistake.

**Every key can be set from the environment** as `ASTERIUS__<TABLE>__<KEY>`,
upper-cased, with `__` between path segments:

```sh
ASTERIUS__DATABASE__URL=postgres://asterius@db:5432/asterius
ASTERIUS__SERVER__BIND=0.0.0.0:9443
ASTERIUS__FEATURES__SSF=true
```

The value is parsed as a TOML scalar, so `true` and `16` mean what they say and
anything that is not valid TOML on its own is taken as a string — which is what
makes an unquoted connection URL work.
";

/// Where secrets come from. Prose, because it is a deployment posture rather
/// than a schema, but it belongs with the keys it talks about.
const SECRETS: &str = "\n\
## Secret sources\n\
\n\
Five values in this file are credentials, and each has a supported production\n\
shape. Nothing here belongs in an image layer, in a `docker-compose.yml` or in\n\
version control; the example stack under `deploy/compose/` uses obvious\n\
development values and says so in every file.\n\
\n\
| Secret | Key | How to supply it |\n\
| --- | --- | --- |\n\
| Key-encryption key | `keys.kek_file` | A file the orchestrator mounts read-only \
(Kubernetes `Secret` volume, Docker secret, systemd credential). Preferred: a \
file is not readable through `/proc/self/environ` and does not appear in a \
process listing. |\n\
| Key-encryption key | `keys.kek_env` | The named variable, injected by the \
orchestrator. Convenient, and second-best. |\n\
| Database password | `database.url` | `ASTERIUS__DATABASE__URL` from the same \
secret store. The value is held redacted in the process and prints as \
`[REDACTED]` wherever the configuration is logged. |\n\
| TLS private key | `server.tls.private_key` | A read-only mount, rotated by \
whatever issues the certificate. The process reads it at startup. |\n\
| Initial access tokens | `registration.initial_access_tokens` | Only needed \
under `mode = \"initial_access_token\"`. Hashed at startup, so the running \
process holds nothing replayable. |\n\
| Deployment admin password | `admin.password_file`, `admin.password_env` | A \
read-only mount, or a variable from the same secret store. Hashed with Argon2id \
at startup, so the database holds no plaintext; the source is read on every boot, \
which is what makes rotating it an edit to the secret and a restart. |\n\
\n\
Rotating the key-encryption key is not a restart with a new value: the old key\n\
must still be able to open existing rows while they are re-wrapped. Until the\n\
rotation runbook lands, treat the KEK as unrotatable and keep it backed up —\n\
losing it loses every signing key in the database.\n\
\n\
### Generating the values\n\
\n\
```sh\n\
# Key-encryption key: 32 bytes, base64.\n\
head -c 32 /dev/urandom | base64 > /etc/asterius/kek\n\
chmod 400 /etc/asterius/kek\n\
\n\
# An initial access token: 128 bits of entropy, base64url, unpadded.\n\
head -c 16 /dev/urandom | basenc --base64url | tr -d '='\n\
```\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::declared_keys;
    use std::collections::BTreeSet;

    /// The reference and the schema must describe the same set of keys.
    ///
    /// This is the whole point of the module. The schema side comes out of the
    /// deserializers, so adding a key to `config.rs` and forgetting it here
    /// fails, and documenting a key the file would reject fails too.
    #[test]
    fn every_key_is_documented() {
        let declared = declared_keys();
        let sections = sections();

        for section in &sections {
            let mut documented: BTreeSet<String> =
                section.keys.iter().map(|k| k.name.clone()).collect();
            // A nested table is a key of its parent: `[server.tls]` is the
            // `tls` key of `[server]`, and `[[tenant]]` is `tenant` at the root.
            documented.extend(
                sections
                    .iter()
                    .filter(|child| child.parent() == Some(section.table))
                    .map(|child| child.key_in_parent().to_owned()),
            );

            let accepted: BTreeSet<String> = declared
                .get(section.table)
                .unwrap_or_else(|| panic!("{} is not a table in the schema", section.table))
                .iter()
                .cloned()
                .collect();

            assert_eq!(
                documented, accepted,
                "table {} documents {documented:?} but accepts {accepted:?}",
                section.table
            );
        }

        assert_eq!(
            sections.len(),
            declared.len(),
            "a table exists in the schema with no section in the reference"
        );
    }

    /// The defaults in the document are the defaults the validator applies.
    ///
    /// Formatted from the same constants, so this asserts the formatting rather
    /// than the values — which is exactly the step where a reference usually
    /// goes wrong, by quoting a number that was true once.
    #[test]
    fn documented_defaults_come_from_the_validator() {
        let sections = sections();
        let find = |table: &str, name: &str| -> String {
            sections
                .iter()
                .find(|s| s.table == table)
                .and_then(|s| s.keys.iter().find(|k| k.name == name))
                .map_or_else(
                    || panic!("{table}.{name} is not documented"),
                    |k| k.default.clone(),
                )
        };

        assert_eq!(find("server", "bind"), "`\"0.0.0.0:9443\"`");
        assert_eq!(find("server", "mode"), "`\"behind_proxy\"`");
        assert_eq!(find("database", "max_connections"), "`16`");
        assert_eq!(find("server", "request_body_limit_bytes"), "`65536`");
        assert_eq!(find(ROOT_TABLE, "log_format"), "`\"text\"`");
    }

    /// Every feature flag in the registry has a row.
    #[test]
    fn every_feature_flag_has_a_row() {
        let names: BTreeSet<String> = features().into_iter().map(|k| k.name).collect();
        for feature in Feature::ALL {
            assert!(
                names.contains(feature.as_str()),
                "feature {feature} has no row"
            );
        }
        assert!(
            features()
                .iter()
                .all(|k| !k.notes.starts_with("Undocumented")),
            "a feature flag has no description in config_reference.rs"
        );
    }

    /// The checked-in document is what this module renders.
    ///
    /// A generated file in version control is only trustworthy if something
    /// fails when it goes stale. The failure message is the command that fixes
    /// it, because that is the only thing the reader needs.
    #[test]
    fn the_checked_in_reference_is_up_to_date() {
        const CHECKED_IN: &str = include_str!("../../../docs/configuration.md");
        assert_eq!(
            render(),
            CHECKED_IN,
            "docs/configuration.md is stale. Regenerate it:\n    {REGENERATE_COMMAND}"
        );
    }

    /// The document quotes the floor the validator actually enforces.
    ///
    /// A number copied into prose is the classic way a reference goes stale, so
    /// the row is formatted from the constant and this asserts that it arrives
    /// in the rendered document rather than being lost in an edit.
    #[test]
    fn the_initial_access_token_floor_is_the_one_the_validator_uses() {
        let rendered = render();
        assert!(
            rendered.contains(&format!(
                "at least {MIN_INITIAL_ACCESS_TOKEN_LEN} characters"
            )),
            "the reference does not quote the validator's minimum token length"
        );
    }
}
