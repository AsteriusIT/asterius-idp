-- A tenant's authorization policy for the AuthZEN PDP (ast-pj0.4).
--
-- One row per tenant holding one document: the ordered rule set ADR-0011
-- decides on, as data. `asterius_domain::policy::RuleSet::parse` validates it
-- on the way in *and* on the way out, so a row this build will not read fails
-- the read rather than being evaluated as the subset of rules it happens to
-- understand — a policy read with its deny rules dropped is worse than no
-- policy at all.
--
-- Its own table rather than a member of `tenants.settings`, for the reason
-- `0016` gives for the theme: it is read on its own path, by the evaluation
-- endpoint (ast-pj0.1) and by nothing else, and a token request must not
-- deserialise a rule catalogue to find a lifetime.
--
-- `document` and not `rules`, `policy` or anything that reads like a secret:
-- the column holds an administrator's rules, never a credential. Nothing here
-- is sealed, nothing is rewrapped by `asterius_store_pg::rewrap`, and that is
-- a property of what is stored rather than an omission.
--
-- Not swept by retention: a policy is configuration and lives as long as the
-- tenant does. `crates/store-pg/src/retention.rs` has to name every table in
-- this schema and says the same thing there.
--
-- The document is JSONB, so it is in the inventory
-- `scripts/sql/json-sentinels-detect.sql` scans: an administrator can put any
-- member name in a rule, and `$serde_json::private::RawValue` as the first
-- member of an object is a row no binary linking serde_json's `raw_value`
-- feature can read back. Repairable in place, because — unlike `audit_events`
-- — nothing here is hash-chained.

create table tenant_policies (
    tenant_id  text primary key references tenants (tenant_id) on delete cascade,
    -- The rule set, as `RuleSet::to_json` writes it: `{"version": 1, "rules":
    -- [...]}`. The two checks below are the cheapest half of what the parser
    -- enforces, repeated here because a row written by anything other than the
    -- adapter -- a restored dump, a migration, a support script -- is still a
    -- row the evaluator will be handed.
    document   jsonb       not null
               check (jsonb_typeof(document) = 'object'
                      and document ? 'version'
                      and jsonb_typeof(document -> 'rules') = 'array'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
