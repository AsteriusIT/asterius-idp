//! Scheduled deletion of the rows that are only meant to exist for a while.
//!
//! RFC 9700 §4.2–4.3 is about credentials leaking; FAPI 2.0 SP §7 is about the
//! authorization server itself being the leak. Both point at the same
//! operational fact: the cheapest way to lose a credential is to keep it after
//! it stopped being useful. An authorization code lives for sixty seconds and a
//! `jti` for the lifetime of one assertion, but the *rows* live until something
//! deletes them, and a store nobody sweeps ends up holding years of expired
//! codes, PAR parameters, session fingerprints and replay markers — a dump of
//! which is a dump of everything anybody ever did here.
//!
//! # The policy is the code
//!
//! [`POLICY`] names **every** table in the schema, and each entry is either the
//! statement that sweeps it or the reason it is kept. The two properties that
//! buys are worth the verbosity:
//!
//! * A statement cannot drift from its rule, because the rule *is* the
//!   statement. There is no second list to update.
//! * A new table added by a later migration with no thought given to retention
//!   fails `retention_policy_names_every_table_in_the_schema`, which is the
//!   failure mode this module exists to prevent. A forgotten table does not
//!   announce itself: it works perfectly and accumulates for a year.
//!
//! # Safe to run on more than one replica
//!
//! Two replicas sweep on the same timer, so both wake up to the same expired
//! rows. Correctness is not the problem — `delete` is idempotent — but doing
//! the work twice is, and so is holding row locks on `jti_replay` while the
//! endpoint that inserts into it is waiting.
//!
//! Two mechanisms, following the precedent set by the migrations at startup and
//! by [`crate::PgKeyRepository`]:
//!
//! * A per-tenant **advisory lock**, taken with `pg_try_advisory_lock` rather
//!   than `pg_advisory_lock`: a second replica that finds the tenant busy
//!   reports [`SweepOutcome::Busy`] and moves on to the next tenant. Waiting
//!   would only buy the right to redo work that has just been done. The lock
//!   lives in the two-key space under `(tenant, 'retention')`, distinct from
//!   the audit sink's one-key space and from key rotation's
//!   `(tenant, 'key-rotation')`, so none of the three can wait on another.
//! * **Batches.** Each statement deletes at most [`BATCH`] rows and commits,
//!   so no transaction holds locks on a hot table for long and a sweep that
//!   falls a million rows behind does not become one enormous transaction. A
//!   table that is still not empty after [`MAX_BATCHES`] passes is left for the
//!   next sweep, reported as [`Sweep::more_to_do`].
//!
//! The advisory lock is a *session* lock rather than a transaction lock,
//! because the batches are separate transactions and a transaction lock would
//! be released after the first one. It is taken on one connection held for the
//! whole sweep, and released explicitly; a connection that dies takes its
//! session locks with it, so a crashed replica cannot wedge a tenant.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgPool, Postgres};
use time::{Duration, OffsetDateTime};

/// What retention does with one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Swept by `statement`, which takes the tenant as `$1`, the cutoff as
    /// `$2` and the batch size as `$3`, and deletes at most `$3` rows.
    ///
    /// `grace` is subtracted from the current time to make the cutoff. It is
    /// zero for most tables — a row whose `expires_at` has passed is a row
    /// nothing will look at again — and non-zero where the *expired* row is
    /// still doing work; see `authorization_codes` in [`POLICY`].
    Sweep {
        /// The batched `delete`.
        statement: &'static str,
        /// How long after expiry the row is still kept.
        grace: Duration,
    },
    /// Never swept, for the stated reason.
    Kept(&'static str),
}

/// One table and what happens to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// The table, exactly as the schema spells it.
    pub table: &'static str,
    /// Swept, or kept and why.
    pub rule: Rule,
}

/// Rows deleted per statement before committing and starting another.
///
/// A thousand rows is a few milliseconds of row locks. Small enough that a
/// concurrent insert into `jti_replay` never waits noticeably, large enough
/// that a backlog is cleared in seconds rather than minutes.
pub const BATCH: i64 = 1_000;

/// The most batches one table gets in one sweep.
///
/// A bound on the pass, not on the work: whatever is left is swept next time.
/// Without it, a first sweep over a store that has never been swept would run
/// for hours on one connection, holding the tenant's lock the whole time.
pub const MAX_BATCHES: usize = 100;

/// Every table in the schema, swept or kept.
///
/// Kept in the schema's own order so that reading this next to
/// `0001_baseline.sql` is a straight comparison.
pub const POLICY: &[Retention] = &[
    Retention {
        table: "tenants",
        rule: Rule::Kept(
            "the root of every cascade; removing a tenant is an operator action \
             with consequences no timer should decide",
        ),
    },
    Retention {
        table: "clients",
        rule: Rule::Sweep {
            // Only for a tenant that asked, and only for a client nobody has
            // used (`ast-cu3`).
            //
            // A registration otherwise lives until it is deleted through RFC
            // 7592, and that is still the default: the predicate reads
            // `unused_client_expiry_seconds` out of the tenant's own
            // registration policy, and a tenant that has not set one — which
            // is every tenant unless an operator typed it — matches no rows at
            // all. `ast-m9c.6` has stored and validated that number since it
            // landed and nothing has ever read it, which is the failure this
            // rule exists to end: a setting that is stored and inert is worse
            // than one that is absent, because an operator believes it is in
            // force.
            //
            // `coalesce(last_used_at, created_at)` is the honest reading of
            // "unused": a client we have never seen authenticate is as idle as
            // its registration is old. 0010 deliberately did not backfill the
            // column, so this is also what every client registered before that
            // migration gets.
            //
            // The interval is built with `make_interval` from a value the
            // *operator* stored through a validating API, never from a request:
            // `RegistrationPolicy::from_json` refuses anything that is not a
            // positive integer, and the cast is to `bigint` so a document that
            // somehow held a larger number errors rather than wrapping.
            statement: "delete from clients where ctid = any (array(
                            select c.ctid
                              from clients c
                              join tenants t on t.tenant_id = c.tenant_id
                             where c.tenant_id = $1
                               and (t.settings -> 'options' -> 'registration_policy'
                                      ->> 'unused_client_expiry_seconds') is not null
                               and coalesce(c.last_used_at, c.created_at) <=
                                   $2 - make_interval(secs => (t.settings -> 'options'
                                          -> 'registration_policy'
                                          ->> 'unused_client_expiry_seconds')::bigint)
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "client_keys",
        rule: Rule::Sweep {
            // A cache of somebody else's JWKS. Past `expires_at` it is not
            // merely useless, it is a set of keys the client may have revoked.
            statement: "delete from client_keys where ctid = any (array(
                            select ctid from client_keys
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "client_key_fetches",
        rule: Rule::Sweep {
            // A negative cache entry (`ast-mxc.8`). Past `next_attempt_at` it
            // no longer suppresses anything: the next fetch goes ahead whether
            // the row is there or not, so keeping it only accumulates a row per
            // URL a client ever mistyped.
            statement: "delete from client_key_fetches where ctid = any (array(
                            select ctid from client_key_fetches
                             where tenant_id = $1 and next_attempt_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "resource_servers",
        rule: Rule::Kept(
            "a registered API is configuration: it is withdrawn by an operator, \
             and a sweep that removed one would refuse every token request \
             naming it (RFC 8707 §3)",
        ),
    },
    Retention {
        table: "authorization_details_types",
        rule: Rule::Kept(
            "a registered authorization details type is configuration: it is withdrawn by an \
             operator, and a sweep that removed one would refuse every pushed request naming it \
             (RFC 9396 §2.1)",
        ),
    },
    Retention {
        table: "users",
        rule: Rule::Kept("an account is deleted by a person, not by a sweep"),
    },
    Retention {
        table: "subject_identifiers",
        rule: Rule::Kept(
            "OIDC Core §8: a subject identifier is never reassigned, so the row \
             that reserves it outlives everything derived from it",
        ),
    },
    Retention {
        table: "retired_subject_identifiers",
        rule: Rule::Kept(
            "a tombstone with an expiry is a `sub` that comes back: the row is \
             the whole of the promise that OIDC Core §8's `never reassigned` \
             survives the account it was issued to (`ast-2vk.12`)",
        ),
    },
    Retention {
        table: "tenant_pairwise_salts",
        rule: Rule::Kept(
            "write-once, enforced by a trigger: deleting a salt would reassign \
             every `sub` in the tenant",
        ),
    },
    Retention {
        table: "credentials",
        rule: Rule::Kept("a passkey or password lives as long as its account"),
    },
    Retention {
        table: "device_codes",
        rule: Rule::Sweep {
            // A device authorization is over the moment it expires: the token
            // endpoint answers `expired_token` off the clock rather than off a
            // status, so nothing reads an expired row again. The row holds the
            // digests of a device code and a user code, which is material a
            // database copy still yields, so it is swept rather than kept.
            //
            // A grace period, unlike most tables here, for the reason
            // `authorization_codes` has one: the *device* is still polling when
            // the authorization expires, and RFC 8628 §3.5 wants it told
            // `expired_token` rather than the "unknown device code" a deleted
            // row would produce. Five minutes is longer than any remaining poll
            // and shorter than anything worth keeping.
            statement: "delete from device_codes where ctid = any (array(
                            select ctid from device_codes
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::minutes(5),
        },
    },
    Retention {
        table: "ciba_requests",
        rule: Rule::Sweep {
            // A backchannel authentication request is over the moment it
            // expires: the token endpoint answers `expired_token` off the
            // clock rather than off a status, so nothing reads an expired row
            // again. The row holds the digest of an `auth_req_id` and, in ping
            // mode, of a `client_notification_token` — both credentials a
            // database copy would otherwise still yield — so it is swept
            // rather than kept.
            //
            // The same five-minute grace `device_codes` has, for the same
            // reason: the client is still polling when its request expires
            // (CIBA Core 1.0 §10.1), and it should be told `expired_token`
            // rather than given the "unknown auth_req_id" a deleted row would
            // produce. Five minutes is longer than any remaining poll and
            // shorter than anything worth keeping, and the row's own lifetime
            // is five minutes at most (`0026_ciba_requests.sql`).
            statement: "delete from ciba_requests where ctid = any (array(
                            select ctid from ciba_requests
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::minutes(5),
        },
    },
    Retention {
        table: "recovery_tokens",
        rule: Rule::Sweep {
            // A reset link, one hour wide. Beside `credentials` because that
            // is what it changes, and swept rather than kept for the reason
            // `0015_account_recovery.sql` gives: the row holds the digest of a
            // live link, and a spent or expired one that stays in the table is
            // material a database copy still yields. `expires_at` alone is the
            // condition — a consumed row is already unusable, and it is the
            // same row, so the one deadline covers both.
            statement: "delete from recovery_tokens where ctid = any (array(
                            select ctid from recovery_tokens
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "user_roles",
        rule: Rule::Kept(
            "authority is granted and revoked by a person: a deployment admin \
             whose role expired on a timer is a deployment nobody can administer",
        ),
    },
    Retention {
        table: "tenant_roles",
        rule: Rule::Kept("a role catalogue is configuration, edited by a person"),
    },
    Retention {
        table: "client_roles",
        rule: Rule::Kept(
            "a client's role catalogue is configuration; it goes when the client does",
        ),
    },
    Retention {
        table: "user_tenant_roles",
        rule: Rule::Kept(
            "an application role is authority delegated to a tenant's own applications, \
             granted and withdrawn by a person; one that expired on a timer would be an \
             authorization change nobody made and nobody can explain",
        ),
    },
    Retention {
        table: "user_client_roles",
        rule: Rule::Kept("the same, for a role that belongs to one client"),
    },
    Retention {
        table: "passkey_enrolments",
        rule: Rule::Sweep {
            // An outstanding registration challenge, five minutes wide. It
            // cascades from `sessions` too, but a session lives for hours and
            // the challenge must not: a row kept past `expires_at` is a
            // challenge that is refused on the clock and still sitting there
            // to be read.
            //
            // Before `sessions`, and that is the only thing the order in this
            // table decides. Either way the row is gone; swept first, it is
            // reported as swept rather than disappearing silently under a
            // cascade, and a sweep whose count for this table is always zero
            // is a rule nobody can tell is working.
            statement: "delete from passkey_enrolments where ctid = any (array(
                            select ctid from passkey_enrolments
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "sessions",
        rule: Rule::Sweep {
            // The absolute deadline only, matching
            // `PgSessionRepository::purge_expired`: an idle session may still
            // be revived by use, and deleting it signs out somebody who was
            // coming back. `session_clients` follows by cascade.
            statement: "delete from sessions where ctid = any (array(
                            select ctid from sessions
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "session_clients",
        rule: Rule::Kept("cascades from `sessions`; a row cannot outlive its session"),
    },
    Retention {
        table: "auth_requests",
        rule: Rule::Sweep {
            // The pushed parameters and the interaction state: `login_hint`,
            // `claims`, whatever the client asked for about the user. FAPI 2.0
            // SP §7 is explicit that this is the material an AS leaks.
            statement: "delete from auth_requests where ctid = any (array(
                            select ctid from auth_requests
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "first_party_interactions",
        rule: Rule::Sweep {
            // The login progress of somebody entering this server's own
            // console: a synchroniser digest and a session digest. Nothing a
            // client pushed, because there is no client — but it is the same
            // material `auth_requests` holds and it is swept on the same terms.
            statement: "delete from first_party_interactions where ctid = any (array(
                            select ctid from first_party_interactions
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "grants",
        rule: Rule::Sweep {
            // Client-only grants, and nothing else.
            //
            // A grant with a person behind it is kept for the reasons it always
            // was: it is the revocable unit of authority — deleting one deletes
            // the only row that could revoke the tokens minted from it — and it
            // is the consent record `asterius_oidc::consent_memory` reads, so a
            // sweep would forget a consent as well as lose a revocation. That
            // memory's own lifetime is enforced when it is read: a standing
            // grant is a standing consent, and an `offline_access` one stops
            // covering new requests after
            // `consent_memory::DEFAULT_OFFLINE_ACCESS_MEMORY` without the row
            // going anywhere. Grant Management ID1 §5.6's unclaimed-grant
            // cleanup is `PgGrantRepository::purge_unclaimed`, on its own
            // schedule and its own predicate.
            //
            // The `client_credentials` grant (RFC 6749 §4.4) has none of that
            // behind it. There is no resource owner, so there is no consent to
            // remember; the row exists so the token it was minted for has
            // something to be revoked through and something for the trail to
            // name (`ast-a05.8`). One row per token request, expiring with a
            // token that lives fifteen minutes: an agent asking for one a
            // minute adds 1 440 rows a day, for ever, and this is the only
            // table in the schema that grows with traffic and was never swept.
            //
            // `user_id`, `subject` and `session_id` all null is what "no
            // resource owner" looks like in this table, and `expires_at not
            // null` keeps the statement away from the standing grants, which
            // have none. A grant that is somebody's parent is left alone
            // whatever it looks like: the self-reference cascades, and a token
            // exchange (RFC 8693) narrowed from a client-only grant would lose
            // its child with it.
            statement: "delete from grants where ctid = any (array(
                            select g.ctid from grants g
                             where g.tenant_id = $1
                               and g.user_id is null
                               and g.subject is null
                               and g.session_id is null
                               and g.expires_at is not null
                               and g.expires_at <= $2
                               and not exists (select 1 from grants child
                                                where child.tenant_id = g.tenant_id
                                                  and child.parent_grant_id = g.grant_id)
                             limit $3))",
            // The window, and the reason it is a constant here rather than a
            // setting: retention has no configured window — every other rule in
            // this table carries its own `grace` — so this is the grant's own
            // `exp` plus a stated margin, on the outbox's precedent. A week is
            // long enough to answer "what was this machine client authorized to
            // do last Tuesday" from the row itself during an incident, and short
            // enough that a client asking for a token a minute holds ten
            // thousand rows rather than an unbounded number. Past it the trail
            // is the durable record: `audit_events` names the `grant_id`, has no
            // foreign key to this table, and is append-only.
            //
            // What the deleted row is *not* still doing: the token it belongs to
            // expired with it, a week ago, so revocation has nothing to revoke —
            // RFC 7009 §2.2's "invalid token", which `/revoke` answers 200 to
            // without ever reading this table, because an expired access token
            // fails verification first. Its `access_token_denylist` and
            // `refresh_tokens` rows, if any existed, expired with the same token
            // and were swept by their own rules; anything left cascades from
            // here, which is the correct order — the grant is the parent.
            grace: Duration::days(7),
        },
    },
    Retention {
        table: "authorization_codes",
        rule: Rule::Sweep {
            statement: "delete from authorization_codes where ctid = any (array(
                            select ctid from authorization_codes
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            // A code expires in sixty seconds (FAPI 2.0 SP §5.3.2.1 item 11)
            // but the *row* is what detects a replay: `PgCodeRepository::redeem`
            // reads `consumed_at` on a code it could not spend, and revokes the
            // grant if it finds one. Delete the row at expiry and a stolen code
            // presented a minute late is an ordinary `invalid_grant` instead of
            // the incident it is (RFC 6749 §10.5, RFC 9700 §4.1.2). A day of
            // rows is a negligible amount of storage and the whole of that
            // signal.
            grace: Duration::days(1),
        },
    },
    Retention {
        table: "refresh_tokens",
        rule: Rule::Sweep {
            // Swept on the *absolute* deadline and on nothing else. The idle
            // deadline is the wrong column for this: it is a rule the
            // redemption applies, and deleting the row on it would make the
            // purge job the thing that decides whether a token is dead. The
            // absolute deadline is the instant past which no reading of the
            // row can accept the token, so it is the instant the row stops
            // being evidence of anything.
            //
            // Revoked-but-unexpired rows stay: the token is still presentable
            // and this row is what refuses it.
            statement: "delete from refresh_tokens where ctid = any (array(
                            select ctid from refresh_tokens
                             where tenant_id = $1 and absolute_expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "access_token_denylist",
        rule: Rule::Sweep {
            // Past `expires_at` the token fails on `exp` without help, so the
            // row stops earning its keep — the schema says so on the table.
            statement: "delete from access_token_denylist where ctid = any (array(
                            select ctid from access_token_denylist
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "access_token_cutoffs",
        rule: Rule::Sweep {
            // A cutoff refuses tokens by their `iat`, and its `expires_at` is
            // the cutoff plus the cap on an access token's lifetime — so past
            // it there is no unexpired token left that the row could refuse,
            // and the row is refusing nothing. Same argument as the denylist
            // above, arrived at from the other end: that table is keyed by the
            // token, this one by the principal.
            statement: "delete from access_token_cutoffs where ctid = any (array(
                            select ctid from access_token_cutoffs
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "jti_replay",
        rule: Rule::Sweep {
            // The single-use marker for client assertions and DPoP proofs, and
            // the fastest-growing table here: one row per authenticated
            // request. Its `expires_at` is the assertion's own `exp`, after
            // which a replay fails on the clock instead.
            statement: "delete from jti_replay where ctid = any (array(
                            select ctid from jti_replay
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "signing_keys",
        rule: Rule::Kept(
            "a retired key's row survives so its `kid` is never handed out \
             twice; the private half is ciphertext under a KEK held elsewhere",
        ),
    },
    Retention {
        table: "key_rotation_schedules",
        rule: Rule::Kept("one row per tenant and algorithm, rewritten rather than accumulated"),
    },
    Retention {
        table: "audit_events",
        rule: Rule::Kept(
            "append-only by trigger, and the trail is the one artefact meant to \
             outlive everything else. Trimming it is \
             `PgAuditSink::purge_older_than`, which announces itself to the \
             trigger — a deliberate operator act against a stated retention \
             window, not a timer",
        ),
    },
    Retention {
        table: "outbox",
        rule: Rule::Sweep {
            // Only rows that have reached a terminal state. A `pending`,
            // `failed` or `claimed` row is work still owed to a relying party,
            // however old it looks, and deleting it would drop a logout
            // notification — a `claimed` one most of all, since its worker may
            // be delivering it right now (`ast-0ju.9`).
            statement: "delete from outbox where ctid = any (array(
                            select ctid from outbox
                             where tenant_id = $1
                               and status in ('delivered', 'abandoned')
                               and coalesce(delivered_at, created_at) <= $2
                             limit $3))",
            // A delivered logout token is evidence for a week: long enough to
            // answer "did the relying party get told" during an incident,
            // short enough that the payloads do not accumulate.
            grace: Duration::days(7),
        },
    },
    Retention {
        table: "outbox_attempts",
        rule: Rule::Kept(
            "swept with its parent and not on a schedule of its own: the rows \
             are `on delete cascade` from `outbox`, so the trail of a delivery \
             disappears exactly when the row it describes does. A second cutoff \
             here would either outlive the row — leaving attempt records for \
             deliveries nobody can look up — or predecease it, emptying the \
             dead-letter screen of the one thing it is read for (`ast-0ju.9`)",
        ),
    },
    Retention {
        table: "initial_access_tokens",
        rule: Rule::Sweep {
            statement: "delete from initial_access_tokens where ctid = any (array(
                            select ctid from initial_access_tokens
                             where tenant_id = $1
                               and expires_at is not null
                               and expires_at <= $2
                             limit $3))",
            // An expired initial access token admits nobody (`ast-cu3`), so
            // the row is only a digest and a spent counter. It is swept and
            // not kept because it is a *credential* record: keeping the
            // digests of every token a tenant ever issued turns a database
            // dump into a list of guesses worth checking against every other
            // deployment the operator runs.
            //
            // A token with no expiry is not swept at any age. `null` there
            // means "until it is deleted", and deleting one on a timer would
            // stop registrations an operator believes are still arranged.
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "rate_limits",
        rule: Rule::Sweep {
            statement: "delete from rate_limits where ctid = any (array(
                            select ctid from rate_limits
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "tenant_themes",
        rule: Rule::Kept(
            "one row per tenant, rewritten rather than accumulated; a palette \
             an administrator chose is not an artefact of one authorization \
             and no timer should decide a tenant stops looking like itself",
        ),
    },
    Retention {
        table: "ssf_streams",
        rule: Rule::Kept(
            "a stream is a receiver's standing configuration (SSF 1.0 §8.1.1), \
             not an artefact of one request: it is created by a `POST` and \
             removed by the `DELETE` of §8.1.1.5, and a sweep that removed one \
             would silently stop a continuous-access signal a security team \
             believes it is still receiving. `inactivity_timeout` is not a \
             cutoff for this policy either — §8.1.1 makes it grounds for the \
             transmitter to *pause* a stream and say so with a \
             stream-updated event (`ast-0ju.5`), which is a decision with a \
             notification attached and not a delete",
        ),
    },
    Retention {
        table: "ssf_stream_subjects",
        rule: Rule::Kept(
            "a stream's subject membership is standing configuration (SSF 1.0 \
             §8.1.3), like the stream itself: a receiver adds a subject with \
             §8.1.3.2 and removes it with §8.1.3.3, and a sweep between the \
             two would silently stop the continuous-access signals a security \
             team believes it is still receiving about that person. The rows \
             do not outlive the stream either — the foreign key cascades — so \
             what is kept is bounded by what receivers asked for and released \
             by the `DELETE` of §8.1.1.5",
        ),
    },
    Retention {
        table: "ssf_poll_queue",
        rule: Rule::Sweep {
            // Every row, on age alone, and deliberately not "only the ones
            // already delivered": RFC 8936 §2.4 makes the *receiver's*
            // acknowledgement the thing that removes a SET, so a row still
            // here after the window is a signal nobody ever came to collect.
            //
            // Unlike `outbox`, where a `pending` row is work this server still
            // owes and performs, nothing here is owed to anyone: poll delivery
            // is pulled, not pushed, and a receiver that has not polled in a
            // month is not a delivery in flight. The row it left behind is a
            // subject identifier held for a third party that never arrived —
            // which is the one thing `asterius_ssf`'s threat model says not to
            // keep a moment longer than the signal is useful.
            statement: "delete from ssf_poll_queue where ctid = any (array(
                            select ctid from ssf_poll_queue
                             where tenant_id = $1
                               and queued_at <= $2
                             limit $3))",
            // A month. A CAEP signal describes a security state that changed:
            // "this session was revoked" is worth acting on for as long as a
            // receiver plausibly takes to come back from an outage, and is
            // worth nothing at all a month later — the session it names has
            // long since expired on its own. The trail keeps the record that
            // the event happened (`ssf.sets_delivered` and the emitter's own
            // entry); what is dropped is the undelivered copy.
            grace: Duration::days(30),
        },
    },
    Retention {
        table: "tenant_theme_assets",
        rule: Rule::Kept(
            "a logo lives as long as the tenant that uploaded it. Content \
             addressed and bounded by the number of uploads an administrator \
             makes, so it does not grow with traffic; an asset the current \
             theme no longer names is kept because reverting a logo change \
             minutes later must not find it swept",
        ),
    },
];

/// What one tenant's sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sweep {
    /// Rows deleted, per table, in [`POLICY`] order. Tables that lost nothing
    /// are absent, so a quiet sweep logs nothing.
    pub deleted: Vec<(&'static str, u64)>,
    /// Whether a table hit its per-sweep batch ceiling and still had rows to
    /// give, so a caller can tell "nothing left" from "still catching up".
    ///
    /// The ceiling itself is not part of this contract — it bounds one pass,
    /// not the work — so what a caller does with a `true` is schedule another
    /// sweep, not compute how much is left.
    pub more_to_do: bool,
}

impl Sweep {
    /// Rows deleted across every table.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.deleted.iter().map(|(_, count)| count).sum()
    }
}

/// The result of asking one tenant to be swept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepOutcome {
    /// This replica held the lock and did the work.
    Swept(Sweep),
    /// Another replica is sweeping this tenant right now. Nothing was done,
    /// which is the correct amount of work to duplicate.
    Busy,
}

/// Deletes expired rows, one tenant at a time.
#[derive(Debug, Clone)]
pub struct PgRetention {
    pool: PgPool,
}

impl PgRetention {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies [`POLICY`] to one tenant.
    ///
    /// Returns [`SweepOutcome::Busy`] without touching a row if another
    /// connection is already sweeping this tenant.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if a connection cannot be acquired or a
    /// statement fails. A failure part-way through leaves the rows it already
    /// deleted deleted: every batch is its own transaction, and there is
    /// nothing to roll back to that would be more correct.
    pub async fn sweep_tenant(
        &self,
        tenant: &TenantId,
        now: OffsetDateTime,
    ) -> Result<SweepOutcome, DomainError> {
        let mut connection = self.pool.acquire().await.map_err(to_domain_error)?;

        let acquired: bool =
            sqlx::query_scalar("select pg_try_advisory_lock(hashtext($1), hashtext('retention'))")
                .bind(tenant.as_str())
                .fetch_one(&mut *connection)
                .await
                .map_err(to_domain_error)?;
        if !acquired {
            return Ok(SweepOutcome::Busy);
        }

        let swept = Self::run(&mut connection, tenant, now).await;
        Self::release(connection, tenant).await;
        swept.map(SweepOutcome::Swept)
    }

    /// One pass over [`POLICY`], with the tenant's lock held.
    async fn run(
        connection: &mut PoolConnection<Postgres>,
        tenant: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Sweep, DomainError> {
        let mut sweep = Sweep::default();

        for entry in POLICY {
            let Rule::Sweep { statement, grace } = entry.rule else {
                continue;
            };
            let cutoff = now - grace;
            let mut removed = 0_u64;

            for batch in 0..MAX_BATCHES {
                let affected = sqlx::query(statement)
                    .bind(tenant.as_str())
                    .bind(cutoff)
                    .bind(BATCH)
                    .execute(&mut **connection)
                    .await
                    .map_err(to_domain_error)?
                    .rows_affected();
                removed += affected;

                if affected < BATCH.unsigned_abs() {
                    break;
                }
                if batch + 1 == MAX_BATCHES {
                    sweep.more_to_do = true;
                }
            }

            if removed > 0 {
                sweep.deleted.push((entry.table, removed));
            }
        }
        Ok(sweep)
    }

    /// Gives the tenant's lock back.
    ///
    /// A failure here is logged rather than returned: the sweep itself
    /// succeeded, and the lock is released by the connection dying in any case.
    /// The connection is closed rather than returned to the pool, because a
    /// pooled connection that still holds the lock would lock the tenant out
    /// until the pool happened to recycle it.
    async fn release(mut connection: PoolConnection<Postgres>, tenant: &TenantId) {
        let released =
            sqlx::query("select pg_advisory_unlock(hashtext($1), hashtext('retention'))")
                .bind(tenant.as_str())
                .execute(&mut *connection)
                .await;

        if let Err(error) = released {
            tracing::warn!(
                %error,
                tenant = %tenant,
                "could not release the retention lock; closing the connection to drop it"
            );
            let _ = connection.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every swept statement has to be tenant-scoped and has to name its own
    /// table. `crate::sql_audit` cannot see these — they are not literals
    /// inside a `sqlx::query!` call — so the same rule is asserted here.
    #[test]
    fn every_swept_statement_is_tenant_scoped_and_names_its_table() {
        for entry in POLICY {
            let Rule::Sweep { statement, .. } = entry.rule else {
                continue;
            };
            assert!(
                statement.contains("tenant_id = $1"),
                "{} is swept without a tenant predicate",
                entry.table
            );
            assert!(
                statement.starts_with(&format!("delete from {} ", entry.table)),
                "the statement filed under {} deletes from somewhere else: {statement}",
                entry.table
            );
            assert!(
                statement.contains("limit $3"),
                "{} is swept unbatched, which locks the table for as long as it takes",
                entry.table
            );
        }
    }

    /// A table filed twice would have one rule silently ignored by the
    /// completeness test, which compares sets.
    #[test]
    fn no_table_is_filed_twice() {
        let mut seen = BTreeSet::new();
        for entry in POLICY {
            assert!(seen.insert(entry.table), "{} appears twice", entry.table);
        }
    }

    /// A kept table has to say why. "Kept" with an empty reason is how a table
    /// nobody thought about gets past review.
    #[test]
    fn every_kept_table_carries_a_reason() {
        for entry in POLICY {
            if let Rule::Kept(reason) = entry.rule {
                assert!(
                    reason.len() > 20,
                    "{} is kept without a reason worth reading",
                    entry.table
                );
            }
        }
    }

    /// The `grants` rule is the one sweep in the policy that must not apply to
    /// every expired row in its table: a user's grant is the consent record and
    /// the revocable unit of authority, and a predicate that lost its
    /// "no resource owner" half would delete both on a timer.
    #[test]
    fn the_grants_sweep_only_reaches_a_grant_with_no_resource_owner() {
        let grants = POLICY
            .iter()
            .find(|entry| entry.table == "grants")
            .expect("grants has a rule");
        let Rule::Sweep { statement, grace } = grants.rule else {
            panic!("client-only grants must be swept");
        };
        for predicate in [
            "user_id is null",
            "subject is null",
            "session_id is null",
            "expires_at is not null",
        ] {
            assert!(
                statement.contains(predicate),
                "the grants sweep is missing `{predicate}` and would take a user's grant"
            );
        }
        assert!(
            grace >= Duration::days(1),
            "a client-only grant deleted the instant its token expires leaves \
             nothing to read during an incident the same day"
        );
    }

    /// The one place a grace period is not zero is the one place it changes
    /// behaviour, so it is worth pinning rather than leaving to a comment.
    #[test]
    fn an_expired_authorization_code_survives_long_enough_to_catch_a_replay() {
        let code = POLICY
            .iter()
            .find(|entry| entry.table == "authorization_codes")
            .expect("authorization_codes has a rule");
        let Rule::Sweep { grace, .. } = code.rule else {
            panic!("authorization codes must be swept");
        };
        assert!(
            grace >= Duration::hours(1),
            "a code row deleted at expiry cannot detect the replay of that code"
        );
    }
}
