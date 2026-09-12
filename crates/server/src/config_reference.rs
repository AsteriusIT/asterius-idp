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
//!   [`Feature::ALL`], the registry that discovery and `/readyz` also read,
//!   minus the flags [`Feature::is_derived`] names — those follow another table
//!   and have no key of their own.
//!
//! What stays prose is what only a person can say: why a key exists and what
//! goes wrong if it is set carelessly. That is the part a reference is for.
//!
//! That prose lives *here*, in [`Key::notes`], [`Section::blurb`],
//! [`Section::after`] and the constants at the end of the file — never in
//! `docs/configuration.md`, which is overwritten in full by [`render`]. Three
//! tickets learned that the expensive way by typing paragraphs into the
//! generated file (`ast-nu8`); the paragraphs are now in this module and the
//! document says at the top that it is generated.

use crate::config::{
    DEFAULT_ADMIN_TENANT, DEFAULT_ADMIN_USERNAME, DEFAULT_BIND, DEFAULT_BODY_LIMIT,
    DEFAULT_LIMIT_ACCESS_EVALUATION_PER_ADDRESS, DEFAULT_LIMIT_ACCESS_EVALUATION_PER_CLIENT,
    DEFAULT_LIMIT_BACKCHANNEL_PER_ADDRESS, DEFAULT_LIMIT_BACKCHANNEL_PER_CLIENT,
    DEFAULT_LIMIT_BACKCHANNEL_PER_USER, DEFAULT_LIMIT_CLIENT_CONFIGURATION_PER_ADDRESS,
    DEFAULT_LIMIT_INTROSPECTION_PER_ADDRESS, DEFAULT_LIMIT_INTROSPECTION_PER_CLIENT,
    DEFAULT_LIMIT_PAR_PER_ADDRESS, DEFAULT_LIMIT_PAR_PER_CLIENT,
    DEFAULT_LIMIT_REGISTRATION_PER_ADDRESS, DEFAULT_LIMIT_SSF_SUBJECTS_PER_ADDRESS,
    DEFAULT_LIMIT_SSF_SUBJECTS_PER_CLIENT, DEFAULT_LIMIT_TOKEN_PER_ADDRESS,
    DEFAULT_LIMIT_TOKEN_PER_CLIENT, DEFAULT_LIMIT_USERINFO_PER_ADDRESS,
    DEFAULT_LIMIT_WINDOW_SECONDS, DEFAULT_LOGIN_MAX_PER_ACCOUNT, DEFAULT_LOGIN_MAX_PER_ADDRESS,
    DEFAULT_LOGIN_WINDOW_SECONDS, DEFAULT_MAX_CONNECTIONS, DEFAULT_MODE, DEFAULT_OUTBOX_BATCH,
    DEFAULT_OUTBOX_LEASE_SECONDS, DEFAULT_OUTBOX_MAX_ATTEMPTS, DEFAULT_OUTBOX_MAX_RETRY_SECONDS,
    DEFAULT_OUTBOX_POLL_SECONDS, DEFAULT_OUTBOX_RETRY_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_TRUSTED_PROXIES, MAX_OUTBOX_BATCH, MIN_LIMIT_WINDOW_SECONDS, MIN_LOGIN_WINDOW_SECONDS,
    MIN_OUTBOX_LEASE_SECONDS, ROOT_TABLE, TransportMode,
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
    /// Prose rendered after the table, or `""`.
    ///
    /// What a row of a table cannot hold: a JSON example, a paragraph about
    /// something the table decides elsewhere. It lives here, in code, because
    /// the document is generated and anything typed into `docs/configuration.md`
    /// is lost at the next regeneration.
    pub after: &'static str,
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
        outbox(),
        tenant(),
        tenant_refresh(),
        admin(),
        dpop(),
        mtls(),
        authzen(),
    ]
}

/// `[authzen]`: how the PDP presents itself, and which of §8's optional APIs
/// it answers (`ast-pj0.3`, `ast-pj0.6`).
fn authzen() -> Section {
    Section {
        table: "authzen",
        heading: "`[authzen]` — the policy decision point's own document",
        blurb: "Read only when `[features] authzen` is on. Whether there is a PDP at \
                all is the flag; this table says how the document that describes it \
                — `/.well-known/authzen-configuration`, Authorization API 1.0 §9.2 — \
                is served, and whether the OPTIONAL Search APIs of §8 are answered. \
                The PDP identifier itself is not a key here and never \
                will be: it is the tenant's issuer, which is the identifier the \
                well-known URL is derived from and the one §9.2.3 has a PEP compare \
                against. A second spelling would be a second identity for a tenant \
                that already has one. `search` is the second key an operator writes \
                that becomes a capability rather than a setting: it derives the \
                `authzen_search` flag, which is why there is no \
                `[features] authzen_search` to contradict it.",
        after: "",
        keys: vec![
            key(
                "signed_metadata",
                "boolean",
                "`false`".to_owned(),
                "Whether the document carries a `signed_metadata` JWT (§9.1.3, the shape \
             RFC 8414 §2.1 defines), signed with the tenant's active key and \
             verifiable against the `jwks_uri` the OP metadata publishes. OPTIONAL in \
             the specification and off here, because a PEP fetching the document over \
             TLS already knows who served it: what the signature adds is a document \
             that stays checkable after it has been stored or passed on, which costs \
             one signature per request and is worth it only where somebody asked. A \
             tenant with no active key serves the document unsigned rather than \
             failing, and says so in the log.",
            ),
            key(
                "search",
                "boolean",
                "`false`".to_owned(),
                "Whether this deployment answers the Search APIs (§8): \
                 `/access/v1/search/subject`, `/access/v1/search/resource` and \
                 `/access/v1/search/action`, advertised as \
                 `search_subject_endpoint`, `search_resource_endpoint` and \
                 `search_action_endpoint` in the PDP document and answering 404 \
                 when this is off. OPTIONAL in the specification and off here, \
                 because a search is a different thing to hand a policy \
                 enforcement point than a decision: an evaluation answers about \
                 one subject the caller already named, and a search enumerates \
                 the subjects, resources or actions of a tenant that satisfy a \
                 policy. Read only where `[features] authzen` is on — there is \
                 nothing to search without a policy decision point — and every \
                 entity returned is evaluated first, so a search never reveals \
                 an access the same caller could not have confirmed one \
                 evaluation at a time.",
            ),
        ],
    }
}

/// `[outbox]`: how queued deliveries are paced and when they are given up on.
fn outbox() -> Section {
    Section {
        table: "outbox",
        heading: "`[outbox]` \u{2014} delivering what was queued",
        blurb: "A back-channel logout, an SSF push, a CIBA ping and an \
                 account-recovery message are all written to one `outbox` table in \
                 the same transaction as the change they describe, and a worker in \
                 every replica delivers them. That is what replaces a message broker \
                 (ADR-0001). These keys pace that worker. **There is no key that \
                 turns it off**: a deployment that queues logout notifications and \
                 never sends them leaves relying parties holding sessions it believes \
                 it ended.",
        after: OUTBOX_NOTES,
        keys: vec![
            key(
                "poll_seconds",
                "integer, at least 1",
                format!("`{DEFAULT_OUTBOX_POLL_SECONDS}`"),
                "How long an idle worker waits before looking again. A worker that \
                 finds a full batch does not wait at all, so this is the latency of \
                 an *idle* deployment and not its throughput. Raising it saves one \
                 statement per replica per second against a mostly empty table and \
                 delays every logout by the same amount.",
            ),
            key(
                "batch",
                "integer, at least 1",
                format!("`{DEFAULT_OUTBOX_BATCH}`"),
                &format!(
                    "At most {MAX_OUTBOX_BATCH}. How many rows one claim takes. The whole batch is claimed under one lease and delivered concurrently inside it, so a batch that cannot be finished within `lease_seconds` has its tail claimed by a second worker and delivered twice."
                ),
            ),
            key(
                "max_attempts",
                "integer, at least 1",
                format!("`{DEFAULT_OUTBOX_MAX_ATTEMPTS}`"),
                "How many times a row is attempted before it becomes a dead letter, \
                 visible at `GET /admin/outbox/dead-letters`. Stamped on each row \
                 when it is written, so changing this affects rows queued afterwards \
                 and never gives a row that has already failed nine times nine more.",
            ),
            key(
                "retry_seconds",
                "integer, at least 1",
                format!("`{DEFAULT_OUTBOX_RETRY_SECONDS}`"),
                "The wait after a first failure. Each further attempt doubles it, \
                 plus up to an eighth derived from the row id, so that a thousand \
                 deliveries to one receiver that failed together do not come back \
                 together.",
            ),
            key(
                "max_retry_seconds",
                "integer, at least `retry_seconds`",
                format!("`{DEFAULT_OUTBOX_MAX_RETRY_SECONDS}`"),
                "The ceiling on that doubling. Without one, a receiver that was down \
                 for a day would next be tried in a week; with it, a receiver that \
                 comes back is found within this long.",
            ),
            key(
                "lease_seconds",
                "integer",
                format!("`{DEFAULT_OUTBOX_LEASE_SECONDS}`"),
                &format!(
                    "At least {MIN_OUTBOX_LEASE_SECONDS} seconds. How long one worker's claim on a row is respected. It is what makes a killed worker's rows deliverable again, and therefore also the longest a delivery can be delayed by a process dying at the wrong moment. Too short and a live worker's row is delivered a second time beside it, which is why the floor sits above the five-second ceiling on outbound requests."
                ),
            ),
        ],
    }
}

/// `[dpop]`: the nonce secret shared between replicas (`ast-a05.11`).
fn dpop() -> Section {
    Section {
        table: "dpop",
        heading: "`[dpop]` — the shared nonce secret",
        blurb: "Only read when the `dpop_nonce` feature is on. **Per process if absent**: \
                each replica then derives nonces from a key it generated at boot, so a \
                nonce issued by one is refused by another and by the same one after a \
                restart. That is safe — RFC 9449 §8's handshake tells the client to retry \
                with the nonce it was just handed — but it turns `use_dpop_nonce` from a \
                once-per-client event into a per-request one, which is the round trip the \
                one-window lookback exists to avoid. Set one secret across every replica \
                and the retry goes back to being rare. Set exactly one of the two keys \
                below; the value is 32 bytes, base64: `head -c 32 /dev/urandom | base64`. \
                It is held redacted in the process and prints as `[REDACTED]` wherever \
                the configuration is logged.",
        after: "",
        keys: vec![
            key(
                "nonce_secret_file",
                "path (**points at a secret**)",
                "per-process secret".to_owned(),
                "The production shape, spelt like `keys.kek_file` and read by the same \
                 parser: the orchestrator mounts the file read-only and it is never in \
                 the image. A file that cannot be read, or that does not hold 32 base64 \
                 bytes, stops the server — an unreadable secret and an absent one would \
                 otherwise look the same, and one of them is a supported deployment.",
            ),
            key(
                "nonce_secret_env",
                "variable name (**names a secret**)",
                "per-process secret".to_owned(),
                "The named variable, injected by the orchestrator. Readable through \
                 `/proc/self/environ`, so the file is preferred. There is no key that \
                 takes the secret itself, for the reason `[admin]` has none.",
            ),
        ],
    }
}

/// `[mtls]`: where client certificates come from (RFC 8705 §2).
fn mtls() -> Section {
    Section {
        table: "mtls",
        heading: "`[mtls]` — client certificates (RFC 8705 §2)",
        blurb: "Read only when `[features] mtls` is on. This table says *how* a \
                certificate reaches the server and whose CAs vouch for it; whether \
                any of it happens is the flag. There is deliberately no `mode` key: \
                whether TLS is terminated here or by a proxy is `[server] mode`, and \
                which peers may speak for a client is `[server.proxy] trusted_cidrs` \
                — the same set that decides whether `X-Forwarded-For` is believed. A \
                second spelling of either would be a second answer to \"who is this \
                server behind\", and behind a proxy the proxy chooses which \
                certificate this server sees, so it can authenticate any client it \
                likes. That is the trust root this table adds; the other is each \
                tenant's CAs, which can mint a certificate for any of that tenant's \
                clients that registered a matching name.",
        after: "",
        keys: vec![
            key(
                "certificate_header",
                "string",
                crate::mtls::DEFAULT_CERTIFICATE_HEADER.to_owned(),
                "The header a reverse proxy forwards the client certificate in — \
                 nginx's `ssl_client_escaped_cert`, HAProxy's `ssl_c_der,base64`. \
                 Percent-encoded PEM, PEM whose newlines the proxy escaped, and \
                 bare base64 DER are all accepted, because they are one certificate \
                 in three transport encodings. **The header is read only from a peer inside \
                 `[server.proxy] trusted_cidrs`**; from anywhere else it is dropped \
                 without being parsed, which is what stops a caller from choosing its \
                 own identity. A proxy that forwards this header must also strip an \
                 inbound one.",
            ),
            key(
                "trust_anchors",
                "table of tenant id to PEM path",
                "none".to_owned(),
                "The CAs each tenant's `tls_client_auth` clients are validated \
                 against (§2.1), one PEM file per tenant. Per tenant and never \
                 global: one process serves several, and a CA one tenant trusts must \
                 not be able to mint clients for another. A tenant with no entry \
                 cannot use the PKI method at all — it fails closed rather than \
                 falling back to the outbound roots, which are for *server* \
                 certificates and would let the public web CAs mint clients. The \
                 `self_signed_tls_client_auth` method (§2.2) needs nothing here: it \
                 matches the certificate against the client's own JWKS. A file named \
                 and unreadable stops the process rather than starting a server that \
                 refuses every client of that tenant.",
            ),
        ],
    }
}

/// Keys that belong to the process rather than to any one table.
fn root() -> Section {
    Section {
        table: ROOT_TABLE,
        heading: "Top level",
        blurb: "Keys that belong to the process rather than to any one part of it.",
        after: "",
        keys: vec![key(
            "log_format",
            "`\"text\"` or `\"json\"`",
            format!("`\"{}\"`", default_log_format()),
            "`json` writes one object per line — `timestamp`, `level`, `target`, a \
             `fields` object and the enclosing `span`, which carries the correlation \
             id — for a log pipeline; `text` is for a terminal. Either way every field \
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
        after: "",
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
        after: "",
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
        after: "",
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
        after: "",
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
        after: "",
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
            key(
                "kek_previous_file",
                "path (**points at a secret**)",
                "optional".to_owned(),
                "The key a rotation is moving *away* from, during the rotation only. A \
                 row that does not open under the current key is retried under this one, \
                 which is what lets `asterius rewrap-kek` run without a window in which a \
                 replica cannot open a row that has already moved. Nothing is ever \
                 written under it. **Remove it once the re-wrap is complete**: while it \
                 is set, a retired key stays readable by this process. See \
                 `docs/runbooks/backup-restore.md` §4.",
            ),
            key(
                "kek_previous_env",
                "variable name (**names a secret**)",
                "optional".to_owned(),
                "The same, from the environment. Set at most one of \
                 `kek_previous_file` and `kek_previous_env`.",
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
                (ADR-0003). One capability is missing from this table on purpose: \
                `dynamic_client_registration` follows `[registration] mode` and has no \
                key here, so that \"who may register\" is written once — see below.",
        after: GRANT_MANAGEMENT_PER_TENANT,
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
        // `ast-m9c.6` and `ast-mxc.8` wrote these two blocks into
        // `docs/configuration.md` by hand, where the next regeneration would
        // have deleted them. A JSON example and a paragraph about a decision
        // taken in another table do not fit in a `| Key | Type |` row, so the
        // generator carries them instead.
        after: r#"`registration.mode` also decides whether the endpoint exists at all. It drives the `dynamic_client_registration` capability, which gates both the `registration_endpoint` member of the discovery document and the route itself (`ast-m9c.6`): a closed deployment advertises no such URL and answers 404 at `/register`, rather than advertising one that refuses everybody. The flag is not writable under `[features]` — writing it there is a configuration error naming the key, because "who may register" belongs in one place.

### Per-tenant registration policy

The deployment's posture is a ceiling, not the whole answer. Each tenant carries a `registration_policy` document in its settings (`PUT /tenants/{id}/settings` in the admin API), and it may only narrow what the deployment allows:

```json
{
  "profile": "agent",
  "mode": "initial_access_token",
  "token_endpoint_auth_methods": ["private_key_jwt"],
  "grant_types": ["client_credentials"],
  "scopes": ["agent:read"],
  "resources": ["https://api.example.com"],
  "redirect_uri_hosts": ["app.example.com"],
  "jwks": "uri",
  "software_statement": {
    "required": true,
    "issuers": [
      { "issuer": "https://vouch.example.com", "jwks_uri": "https://vouch.example.com/jwks" }
    ]
  },
  "max_clients_per_initial_access_token": 25,
  "unused_client_expiry_seconds": 2592000,
  "rotate_registration_access_token": false,
  "registration_access_token_grace_seconds": 300
}
```

Every member is optional and every list is *closed*: an absent list means "this tenant has no opinion", and an empty one means "none". `mode: "closed"` removes the endpoint from that tenant's discovery document and unmounts its route; `mode: "open"` cannot open an endpoint the deployment gated. `profile: "agent"` selects the preset for onboarding agents — `client_credentials` only, no callbacks, a software statement required, a quota and an expiry — which the other members then override; a policy that requires a statement and names no trusted issuer is refused, because nothing could ever register under it.

A software statement issuer is a **root of trust**: RFC 7591 §2.3 makes a statement's claims override the request's, so whoever holds that signing key can create clients in this tenant with metadata of their choosing. Both URLs must be `https`, the `iss` is compared byte-exactly, and the keys are fetched through the one outbound path. See `docs/threat-model.md`.

Both quota members are enforced since `ast-cu3`:

* **`max_clients_per_initial_access_token`** is stamped onto every token the admin API issues for this tenant (`POST /admin/api/v1/initial-access-tokens`), and charged atomically at `POST /register`. It applies to the tenant's own tokens, which are rows; the initial access tokens an operator configures in this file belong to the *deployment* and still have no quota. A tenant that sets `mode: "initial_access_token"` therefore stops accepting the deployment's tokens and starts accepting only its own — which is the point, and which means such a tenant must issue at least one token before anybody can register.
* **`unused_client_expiry_seconds`** is honoured by the retention sweep: a client that has not authenticated at the token endpoint or PAR for that long is deleted, dated by `clients.last_used_at` and falling back to `created_at` for a client that has never authenticated. A tenant that sets nothing here keeps every client for ever, which stays the default. `last_used_at` is written at most once per client per hour, so the value is accurate to the hour against a window measured in days.

### Rotating the registration access token

`rotate_registration_access_token` takes RFC 7592 §5's "MAY be rotated when the developer or client does a read or update operation", for updates only and only where a tenant asks. **It is `false` unless the tenant sets it**, and that default is a decision: this server issues no client secret (FAPI 2.0 SP §5.3.2.1), so the registration access token is a client's only credential and there is no re-issue path. A rotation whose `200` is lost in transit would otherwise strand the client for good — the state §5 tells implementers to avoid.

* **A `PUT /register/{client_id}` rotates.** The response carries the new `registration_access_token`, which is the only time the client will see it; the server keeps a digest.
* **A `GET` never rotates**, whatever the policy says. OIDC Registration §4.3: "since Read operations are intended to be idempotent, the Client Read Request itself SHOULD NOT cause changes."
* **The previous token keeps working for `registration_access_token_grace_seconds`** — 300 by default, one hour at most — so a client that never received the response can retry with the token it still holds and be handed a new one. The window covers a lost response, not two credentials in parallel: the **first** request authenticated with the new token retires the old one immediately, whatever the window had left. Past the window the old token is refused with the same 401 an unknown client gets.

Each rotation is recorded in the audit trail as `client.credential_rotated`, naming the client and the moment and never the token. A rotation that could not be written is not announced: the response is a `200` with no `registration_access_token`, and the client keeps the credential it has."#,
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
        after: "",
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
#[expect(
    clippy::too_many_lines,
    reason = "one key per configurable limit, each with the prose an operator reads before \
              changing it; splitting the list in two would put half the table in another \
              function and invite a key to be documented in neither"
)]
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
        after: ACCOUNT_RECOVERY_AND_MAIL,
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
            key(
                "introspection_per_address",
                "integer",
                DEFAULT_LIMIT_INTROSPECTION_PER_ADDRESS.to_string(),
                "Requests per window to `POST /introspect` (RFC 7662) from one \
                 address. Sized like UserInfo's and for the same reason: the callers \
                 are resource servers, and one address is legitimately a fleet making \
                 a request per API call.",
            ),
            key(
                "introspection_per_client",
                "integer",
                DEFAULT_LIMIT_INTROSPECTION_PER_CLIENT.to_string(),
                "The same, per authenticated caller — and the bucket that matters \
                 here. RFC 7662 §2.1 authenticates the caller before anything is \
                 looked up, so there is always a proven client to charge, and this is \
                 what prices §4's token scanning: every answer to a scan is a 200 \
                 saying `active: false`, so nothing in the protocol tells a caller \
                 walking token values to stop.",
            ),
            key(
                "ssf_subjects_per_address",
                "integer",
                DEFAULT_LIMIT_SSF_SUBJECTS_PER_ADDRESS.to_string(),
                "Requests per window from one address to the SSF add-subject and \
                 remove-subject endpoints (SSF 1.0 §8.1.3.2, §8.1.3.3). Tight, because \
                 those endpoints answer the same way whether or not a subject exists \
                 (§9.1) and the remaining way to probe for one is volume.",
            ),
            key(
                "backchannel_per_address",
                "integer",
                DEFAULT_LIMIT_BACKCHANNEL_PER_ADDRESS.to_string(),
                "Requests per window from one address to `POST /bc-authorize` (CIBA \
                 Core 1.0 §7.1). Tighter than the token endpoint's, because each \
                 accepted request sends a person a message and puts a decision in \
                 front of them.",
            ),
            key(
                "backchannel_per_client",
                "integer",
                DEFAULT_LIMIT_BACKCHANNEL_PER_CLIENT.to_string(),
                "The same, per authenticated client. Above the address limit, because \
                 several clients can share one address and a client that proved who it \
                 is should not be bounded by traffic it did not make.",
            ),
            key(
                "backchannel_per_user",
                "integer",
                DEFAULT_LIMIT_BACKCHANNEL_PER_USER.to_string(),
                "Backchannel requests per window about *one person*, whichever client \
                 asks and whichever hint names them. The limit that bounds approval \
                 fatigue: a client with a large budget spread over a directory is \
                 ordinary traffic, and the same budget aimed at one account is an \
                 attack. Raise it only if a deployment legitimately asks the same \
                 person several times a minute.",
            ),
            key(
                "ssf_subjects_per_client",
                "integer",
                DEFAULT_LIMIT_SSF_SUBJECTS_PER_CLIENT.to_string(),
                "The same, per authenticated receiver. Higher than the address limit, \
                 because several receivers can share one address and a receiver \
                 bringing a deployment online adds its subjects in a burst.",
            ),
            key(
                "access_evaluation_per_address",
                "integer",
                DEFAULT_LIMIT_ACCESS_EVALUATION_PER_ADDRESS.to_string(),
                "Access evaluation requests per window from one address (AuthZEN \
                 Authorization API 1.0 §11.7). As generous as UserInfo's, because the \
                 callers are machines: a policy enforcement point asks once per API \
                 call it protects.",
            ),
            key(
                "access_evaluation_per_client",
                "integer",
                DEFAULT_LIMIT_ACCESS_EVALUATION_PER_CLIENT.to_string(),
                "The same, per authenticated enforcement point. Higher than the address \
                 limit, because several PEPs can share one address; this is the bucket \
                 that matters, since every request here carries a verified token.",
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
        after: "",
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
        after: "",
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
        after: "",
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

/// The `[features]` rows, one per flag an operator may write.
///
/// Generated from [`Feature::ALL`] so that a flag added to the registry appears
/// here without anybody remembering to add it, which is the failure mode this
/// whole module exists to prevent. Derived flags — the ones
/// [`Feature::is_derived`] names, which the `[features]` deserializer refuses —
/// are left out: a row for a key the file rejects would be an instruction that
/// stops the server, which is worse than no row. Their section says where they
/// come from instead.
fn features() -> Vec<Key> {
    let defaults = Capabilities::default();
    Feature::ALL
        .into_iter()
        .filter(|feature| !feature.is_derived())
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
                    // `ast-lh3.7`: on today, this validates and stores CIBA
                    // client metadata and advertises nothing, because there is
                    // no backchannel authentication endpoint yet (`ast-lh3.4`)
                    // and CIBA Core 1.0 §4's OP metadata is REQUIRED as a set.
                    // The sentence changes when the endpoint does.
                    Feature::Ciba => {
                        "CIBA Core 1.0 backchannel authentication, poll and ping. There is no \
                         backchannel authentication endpoint yet, so switching this on \
                         validates and stores CIBA client metadata and advertises nothing: the \
                         discovery document names neither the endpoint, nor the delivery modes, \
                         nor the grant type."
                    }
                    Feature::DeviceFlow => "Device Authorization Grant (RFC 8628).",
                    Feature::TokenExchange => "Token Exchange (RFC 8693) with delegation chains.",
                    Feature::Ssf => "Shared Signals Framework transmitter and CAEP/RISC events.",
                    Feature::Authzen => "AuthZEN Authorization API 1.0 policy decision point.",
                    Feature::DpopNonce => "Server-issued DPoP nonces (RFC 9449 §8).",
                    Feature::RequestObject => {
                        "Signed request objects inside a pushed request (JAR, RFC 9101)."
                    }
                    Feature::SelfRegistration => {
                        "Self-service account registration: `prompt=create` (OpenID Connect \
                         Prompt Create 1.0 §3) and the sign-up page it lands on. With it off, \
                         `prompt_values_supported` does not name `create`, a pushed request \
                         asking for it is refused, and no interaction can reach the sign-up \
                         page — so a tenant that provisions its accounts neither advertises \
                         the value nor creates an account for one."
                    }
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
        if !section.after.is_empty() {
            let _ = writeln!(out, "\n{}", section.after);
        }
    }

    let _ = out.write_str(CLIENT_KEY_FETCHES);
    let _ = out.write_str(SECRETS);
    out
}

/// What a row of the `[outbox]` table cannot hold.
const OUTBOX_NOTES: &str = "\
Delivery is **at-least-once**. A worker claims a row, commits the claim, then \
delivers; a process killed between the two leaves a claim that lapses, and the \
next worker delivers the row again under the same identifier. Every receiver \
must therefore deduplicate \u{2014} on the logout token's `jti` for back-channel \
logout, on the SET's `jti` for a Shared Signals push. The alternative, marking \
a row delivered before it has been, loses a logout every time a pod is \
evicted, and a logout that never arrives is a session a relying party keeps \
after this server ended it.\n\
\n\
Events that must not overtake one another carry an **ordering key** \u{2014} \
`(stream, subject)` for a Shared Signals stream, `(client, session)` for \
back-channel logout \u{2014} and a row is not claimed while an earlier row with \
the same key is still owed. One wedged key therefore holds its own queue and \
no other, which is the trade: order within a key, concurrency between them.\n\
\n\
A row that exhausts `max_attempts` becomes a **dead letter**. It is listed at \
`GET /admin/outbox/dead-letters` with its kind, its attempt count and the last \
error, and deliberately without its payload or its destination: an abandoned \
`notification.account_recovery` payload is a live password-reset link and its \
destination is the address of the person it was for. Whoever is entitled to \
those reads the database.\n\
\n\
Two metrics come out of this: `asterius_outbox_deliveries_total`, labelled by \
event family and outcome, and `asterius_outbox_backlog`, the number of rows \
not yet delivered or abandoned. The backlog is the one worth alerting on \u{2014} \
it grows without bound when a receiver stops accepting or a worker stops \
running, and neither announces itself.\n";

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

/// The one Grant Management setting a tenant carries of its own (`ast-uwv.4`).
/// Prose rather than a `[features]` row, because it is set per tenant through
/// the admin API and not in this file at all.
const GRANT_MANAGEMENT_PER_TENANT: &str = "\
### Per-tenant Grant Management settings\n\
\n\
`features.grant_management` is the ceiling. A tenant may switch the feature off in its own settings like any other, and two settings of its own sit beside it:\n\
\n\
| Setting | Type | Default | Notes |\n\
| --- | --- | --- | --- |\n\
| `grant_management_action_required` | boolean | `false` | Grant Management ID1 §7.1. When true, an authorization request that names no `grant_management_action` is refused with `invalid_request`, and the discovery document publishes `grant_management_action_required: true`. Ignored — and never published — for a tenant that does not offer Grant Management, because a tenant cannot require a parameter it also ignores. |\n\
| `grant_id_in_access_token` | boolean | `true` | RFC 9068 §2.2.3.1's private claim. On by default, because it is what every token this server has ever issued carried and what its own UserInfo endpoint resolves a grant through. Switch it off where the resource servers are all third parties: §6 calls the claim a correlator, and two tokens carrying the same one tell a resource server they came from a single authorization. With it off, UserInfo falls back to the token's `client_id` and `sub` — which cannot tell two live grants of one person to one client apart, and refuses rather than guessing. Independent of `features.grant_management`. |\n\
| `revoke_refresh_on_logout` | boolean | `false` | OIDC Back-Channel Logout 1.0 §2, `ast-o4u.2`. When true, ending a session at `/logout` also revokes the refresh tokens issued under it and withdraws the access tokens minted from those grants (RFC 7009 §2.1). Off by default, and the default is a decision: a refresh token is offline access a person granted a client, not part of a browser session, so a deployment whose clients hold `offline_access` would find every integration broken by somebody signing out of the console. Turn it on where every client is a first-party browser application and \"log out\" is meant to mean everywhere. |\n\
\n\
With `features.grant_management` off, `grant_id` and `grant_management_action` are ignored rather than refused, and the discovery document carries neither `grant_management_actions_supported` nor `grant_management_action_required`. A client that sends the parameters to such a deployment gets the ordinary authorization a server built before the draft would have given it.\n\nWith `features.grant_management` on, `GET` and `DELETE` are served at `grant_management_endpoint` + `/` + the grant id (§6.3). The endpoint is its own resource server: a client asks for a token with `resource` set to `grant_management_endpoint` and one of §6.1's two scopes, `grant_management_query` or `grant_management_revoke`, and nothing needs registering for that audience to exist. The client's own resource allow-list still applies, so a client that has one must have the grant management endpoint on it.\n\
\n\
### Per-tenant account settings\n\
\n\
| Setting | Type | Default | Notes |\n\
| --- | --- | --- | --- |\n\
| `require_verified_email` | boolean | `false` | `ast-vae`. When true, an account whose address has not been proved cannot finish an OIDC login here: the credential is accepted, no session is created, no authorization code is issued, and the browser gets the confirmation page with a fresh link already sent. Off by default, and the default is a decision — turning it on puts a mailbox in the path of every sign-in, so an account whose address has stopped working can no longer be used at all. An account with **no** address is not blocked, because the setting is about proving an address rather than requiring one, and a tenant whose accounts were provisioned passkey-only would otherwise lock out everybody at once. OIDC Core §5.1's `email_verified` is reported honestly to relying parties either way; what this decides is whether an unproved address blocks. |\n\
\n\
The confirmation routes (`GET /verify-email?token=…` and `POST /verify-email`) are mounted whatever this setting says, so a tenant that switches the gate on after accounts exist does not invalidate the links its outstanding messages already carry, and one that switches it off does not strand the people mid-flow. The token is 256 bits, single use, fifteen minutes, stored as a digest, and handed to the outbox in the same transaction as the row that describes it.";

/// What an operator must know before switching passwords on (`ast-2vk.10`).
/// There is no key to document — recovery is mounted with the interaction
/// pages — and that absence is exactly what an operator has to be told.
const ACCOUNT_RECOVERY_AND_MAIL: &str = "\
## Account recovery and mail — read this before enabling passwords\n\
\n\
**This repository ships no mail sender, and nothing you configure here will\n\
make one appear.** Account recovery is built and wired; delivery is not.\n\
\n\
The recovery pages (`GET|POST /recovery`, `GET|POST /recovery/new`) are mounted\n\
whenever the deployment has the database wiring for the interaction pages —\n\
there is no flag. Requesting a link produces a real single-use token and hands\n\
a message to the configured `MailSender`. The only adapter in this repository\n\
is a **journal**: it writes the message to the transactional `outbox` table,\n\
logs that it queued it, and delivers nothing. `delivered_at` stays null,\n\
because it was not delivered.\n\
\n\
That shape is deliberate rather than a stub. A deployment gets a complete,\n\
queryable record of which recovery links were produced and for whom, tests can\n\
read the link a browser would have been mailed, and nobody is misled into\n\
thinking mail works. Wiring a real sender means implementing\n\
`asterius_domain::MailSender` — one method, `send(&Notification)` — and\n\
substituting it where `asterius_store_pg::PgOutboxMailSender` is built. There\n\
is deliberately no SMTP dependency anywhere in the protocol crates; the\n\
layering check enforces that.\n\
\n\
**Operational consequences, in order of how much they will cost you:**\n\
\n\
* **Nobody can recover an account until you wire a sender.** Until then the\n\
\x20\x20outbox is the only place the link exists — an operator can read it out and\n\
\x20\x20pass it on, which is a manual process and should be treated as one.\n\
* **Treat the outbox as a credential store.** An `account_recovery` row\n\
\x20\x20contains a live reset link until the token behind it expires, fifteen minutes\n\
\x20\x20later. Keep retention on that table short and its access narrow. The\n\
\x20\x20retention sweep already ages it; the default is not tuned for this.\n\
* **The mail path is now inside the trust boundary of every account with an\n\
\x20\x20address.** A gateway that expands links to preview them will spend them. A\n\
\x20\x20shared inbox is a shared account. See `docs/threat-model.md`, \"Account\n\
\x20\x20recovery\".\n\
* **Recovery sets a password.** An account whose only credential was a passkey\n\
\x20\x20is recovered onto a weaker method. A deployment that wants passkeys only\n\
\x20\x20should leave `[admin]`/password material unconfigured, which makes the\n\
\x20\x20new-password step refuse rather than downgrade.\n\
* **Requests are counted against `[login]`'s buckets**, not a limiter of their\n\
\x20\x20own: a burst of reset requests for one identifier consumes the same budget a\n\
\x20\x20burst of wrong passwords would. Size `login.max_failures_per_account` with\n\
\x20\x20that in mind.\n\
\n\
Recovery mail is not the only thing the journal carries: a completed recovery\n\
also queues a `credential_changed` notice to the account. That one has nothing\n\
to click, on purpose.";

/// Outbound traffic that no key switches on. Prose, because there is nothing to
/// configure — and here anyway, because it is traffic this deployment sends to
/// somebody else's server and the operator of that server notices it first.
const CLIENT_KEY_FETCHES: &str = "\n\
## Client key fetches — outbound traffic you did not ask for\n\
\n\
Not configurable, and here because it is traffic your deployment sends to \
somebody else. A client registered with a `jwks_uri` has its key set fetched by \
this server; a fetch that fails is remembered so that a broken — or third-party \
— URL is not fetched again on every request naming that client. The intervals \
are built in: keys are served for 10 minutes before they are fetched again, an \
unknown `kid` provokes at most one refresh per client per 60 seconds, and a \
failed fetch suppresses the next one for 60 seconds.\n\
\n\
Those last 60 seconds are a *shared* decision, not a per-process one. Each \
failure writes a row to `client_key_fetches` — the tenant, the client, a \
SHA-256 of the URL, the reason, and the instant before which nobody fetches \
again — and every replica reads it before opening a socket. Without that table \
the interval would be divided by the number of replicas you run and reset by \
every restart, which is a rate nobody chose and which the operator of the URL, \
not you, would notice first. The reason is bounded and the URL is only ever \
stored as a digest, because a `jwks_uri` may carry a query parameter the client \
considers a secret.\n\
\n\
Rows are removed when a fetch for that URL succeeds, and swept by the retention \
pass once their window has passed; nothing here needs an operator's attention \
unless the table is growing, which means clients are registering `jwks_uri` \
values that never work.\n";

/// Where secrets come from. Prose, because it is a deployment posture rather
/// than a schema, but it belongs with the keys it talks about.
const SECRETS: &str = "\n\
## Secret sources\n\
\n\
Six values in this file are credentials, and each has a supported production\n\
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
| DPoP nonce secret | `dpop.nonce_secret_file`, `dpop.nonce_secret_env` | Only \
meaningful under `features.dpop_nonce`. The same shapes and the same parser as \
the key-encryption key, and the same 32 bytes of base64. Absent means per-process \
nonces, which is a round trip rather than a failure. |\n\
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

    /// Every writable feature flag has a row, and no derived one has.
    ///
    /// Both directions matter. A missing row hides a capability; a row for a
    /// flag the `[features]` deserializer refuses tells an operator to write a
    /// key that stops the server at boot.
    #[test]
    fn every_feature_flag_has_a_row() {
        let names: BTreeSet<String> = features().into_iter().map(|k| k.name).collect();
        for feature in Feature::ALL {
            assert_eq!(
                names.contains(feature.as_str()),
                !feature.is_derived(),
                "feature {feature} is {} but {} a row",
                if feature.is_derived() {
                    "derived"
                } else {
                    "writable"
                },
                if names.contains(feature.as_str()) {
                    "has"
                } else {
                    "has no"
                }
            );
        }
        assert!(
            features()
                .iter()
                .all(|k| !k.notes.starts_with("Undocumented")),
            "a feature flag has no description in config_reference.rs"
        );
    }

    /// A flag with no key is still described somewhere in the document.
    ///
    /// Leaving a derived flag out of the `[features]` table is only honest if
    /// the reader is told where it comes from; otherwise a capability that
    /// shows up on `/readyz` appears in no documentation at all.
    #[test]
    fn a_derived_flag_is_named_in_the_document() {
        // Arrange
        let rendered = render();

        // Act
        let derived = Feature::ALL.into_iter().filter(|f| f.is_derived());

        // Assert
        for feature in derived {
            assert!(
                rendered.contains(feature.as_str()),
                "{feature} has no row and no prose: an operator cannot find it"
            );
        }
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
