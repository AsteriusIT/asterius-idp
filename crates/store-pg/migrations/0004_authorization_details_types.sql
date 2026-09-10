-- Registered authorization details types per tenant (RFC 9396, `ast-gxh.6`).
--
-- RFC 9396 §2.1: the types "are defined by the API designers". So a `type` is
-- a thing the operator registers — a name, the schema an element of that type
-- must satisfy, and the sentence the consent page shows the user — and a type
-- this deployment never heard of is refused rather than passed through. An
-- unregistered type reaching a grant would be an authorization nobody could
-- describe to the user and no resource server could interpret.
--
-- A migration of its own rather than an edit to the baseline, for the reason
-- 0002 gives: editing a baseline changes a checksum sqlx refuses to run against
-- a database that already applied it, and the databases this repository is
-- developed against are shared.

create table authorization_details_types (
    tenant_id        text        not null
                                 references tenants (tenant_id) on delete cascade,
    -- The `type` value a client sends, compared byte for byte. RFC 9396 gives
    -- no normalisation, so none is applied here either: two spellings must not
    -- both match one registration. Printable ASCII without space, quote or
    -- backslash — the same bound `asterius_domain::authorization_details::
    -- is_type_name` applies, restated here because a row is not only written by
    -- that path, and because this name ends up in an access token claim, on a
    -- consent page and in a log line.
    type_name        text        not null
                                 check (type_name ~ '^[!-~]{1,128}$'
                                        and type_name !~ '["\\]'),
    -- The schema an element of this type must satisfy. A JSON Schema document
    -- restricted to the subset `asterius_domain::authorization_details::Schema`
    -- validates against; `{}` is "no constraint beyond the shape RFC 9396 §2
    -- requires", which is what a type gets before an operator has described it.
    -- Not null and defaulted, because a null schema and an empty one would be
    -- the same thing to every reader and only one of them can be checked.
    schema           jsonb       not null default '{}'::jsonb
                                 check (jsonb_typeof(schema) = 'object'),
    -- The sentence shown to the user on the consent page. Null is an operator
    -- who registered a type without describing it: the page then says the type
    -- is undescribed rather than falling back to the raw JSON, which is
    -- attacker-composed text nobody reads (RFC 9396 §12).
    consent_template text        check (length(consent_template) <= 512),
    description      text,
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now(),

    -- One row per type per tenant, the tenant first, like every other key here:
    -- a type name is only meaningful inside the tenant that defined it, and two
    -- tenants may legitimately register the same name for different things.
    primary key (tenant_id, type_name)
);

create trigger authorization_details_types_set_updated_at
    before update on authorization_details_types
    for each row execute function set_updated_at();
