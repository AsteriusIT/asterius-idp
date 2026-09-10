-- A tenant's design tokens, and the images they name (ast-ndk.1).
--
-- Two tables rather than a member of `tenants.settings`, for one reason each.
--
-- `tenant_themes` is a document, like the settings one, and it could have
-- lived beside them. It does not, because the theme is read on a different
-- path: the settings document is read when an authorization decision needs a
-- lifetime, and the theme is read when a *page* is rendered. Keeping them
-- apart means a page render never deserialises a FAPI lifetime and a token
-- request never reads a palette.
--
-- `tenant_theme_assets` holds blobs, and a blob has no business in a row that
-- anything reads on the request path. It is keyed by the digest of the stored
-- bytes — content addressing — so uploading the same logo twice is one row and
-- the theme document can name an asset by a value that is also a safe path
-- segment. The bytes are always this server's own re-encoding: nothing writes
-- an upload here (`asterius_admin_api::theme_image`).
--
-- Both cascade from `tenants`, and neither is swept: see
-- `crates/store-pg/src/retention.rs`, which has to name every table in this
-- schema.

create table tenant_themes (
    tenant_id  text primary key references tenants (tenant_id) on delete cascade,
    -- Validated by `asterius_domain::Theme::from_json` on the way in and on
    -- the way out. A document this build refuses fails the read rather than
    -- falling back to the defaults, deliberately.
    document   jsonb       not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table tenant_theme_assets (
    tenant_id    text        not null references tenants (tenant_id) on delete cascade,
    -- sha-256 of `bytes`, lowercase hex, checked by the domain before it ever
    -- reaches a URL. The constraint repeats that here because this column is
    -- what a path segment is built from, and a row written by something other
    -- than the adapter would otherwise be a path traversal waiting for a
    -- handler.
    digest       text        not null check (digest ~ '^[0-9a-f]{64}$'),
    -- The media type the bytes are served as. Closed set: an SVG is refused
    -- long before this table, and a row claiming one would be active content
    -- served from the tenant's own origin.
    content_type text        not null check (content_type in ('image/png', 'image/jpeg', 'image/webp')),
    bytes        bytea       not null,
    created_at   timestamptz not null default now(),
    primary key (tenant_id, digest)
);
