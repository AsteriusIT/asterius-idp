-- Registered resource servers per tenant (RFC 8707, `ast-gxh.7`).
--
-- A `resource` parameter names an API, and an API is a thing the operator
-- knows about: which identifier it answers to, which scopes it understands,
-- how long a token for it should live. Without this table the `aud` of an
-- access token would be whatever a client sent, which is the check RFC 8707 §3
-- ("the authorization server MUST validate the resource parameter") exists to
-- require.
--
-- A migration of its own rather than an edit to the baseline: the baseline is
-- still editable before the first release, but editing it changes a checksum
-- sqlx refuses to run against a database that already applied it, and the
-- databases this repository is developed against are shared. Adding a file
-- costs one row in `_sqlx_migrations` and no reset.

create table resource_servers (
    tenant_id             text        not null
                                      references tenants (tenant_id) on delete cascade,
    -- The identifier a client names in `resource` and a token carries in `aud`.
    -- RFC 8707 §2: an absolute URI with no fragment. The check is the same
    -- shape `tenants.default_resource` carries, plus the explicit refusal of a
    -- fragment, so a value that could never be a legitimate audience cannot be
    -- stored and then discovered at the moment a token is signed.
    identifier            text        not null
                                      check (identifier ~ '^https?://[^#]+$'),
    -- What this resource server understands. Null is "no opinion, whatever the
    -- grant carries"; an empty array is a resource server that understands no
    -- scopes at all. The two are different configurations, which is why the
    -- column is nullable rather than defaulted to '{}'.
    scopes                text[],
    -- The operator's opinion on how long a token for this API lives, in
    -- seconds. Null is "use the tenant's". Issuance keeps its own ceiling
    -- whatever this says.
    token_lifetime_seconds integer    check (token_lifetime_seconds > 0),
    description           text,
    created_at            timestamptz not null default now(),
    updated_at            timestamptz not null default now(),

    -- One row per identifier per tenant, and the tenant first, like every
    -- other key here: a resource identifier is only meaningful inside the
    -- tenant that registered it, and two tenants may legitimately front the
    -- same API.
    primary key (tenant_id, identifier)
);

create trigger resource_servers_set_updated_at before update on resource_servers
    for each row execute function set_updated_at();

-- Every tenant that exists today gets its own `default_resource` registered,
-- because that is the audience its tokens already carry: without this row the
-- first token request after this migration would find an unregistered default
-- audience and be refused `invalid_target`. A migration that turned working
-- deployments off would be a worse answer than one that writes the row the
-- deployment has been behaving as if it held.
insert into resource_servers (tenant_id, identifier, description)
select tenant_id, default_resource, 'the tenant default audience, registered by 0002'
  from tenants
 where default_resource ~ '^https?://[^#]+$'
    on conflict do nothing;
