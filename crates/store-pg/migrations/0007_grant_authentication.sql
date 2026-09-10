-- The authentication a grant was made in, copied onto the grant (`ast-dlk`).
--
-- OIDC Core §11 defines `offline_access` as access "when the End-User is not
-- present", so such a grant is meant to outlive the browser session it was
-- created in. Until now `auth_time`, `acr` and `amr` were read from the
-- `sessions` row and from nowhere else, so a purge, a sign-out or a retention
-- policy left the server with no honest answer to "when did this person
-- authenticate" and it refused to refresh at all — the residue `ast-uwv.3`
-- named: the consent memory it delivered is *derived* from the grants, and a
-- derivation has nowhere to keep an `auth_time`.
--
-- Three columns rather than a join: the session row is exactly the thing that
-- may be gone, so a foreign key would point at nothing by the time it is
-- needed. They are a snapshot taken when the authorization completed, and the
-- session — while it exists — stays the live answer; see
-- `asterius_server::http::issuance::session_facts`.
--
-- All three are nullable, and a `client_credentials` grant (RFC 6749 §4.4)
-- leaves them null: it names no person, so there is no authentication to
-- record and nothing for the fallback to read.
alter table grants
    -- Not named `auth_time`: this is the instant, in the column type the rest
    -- of the schema uses, and `auth_time` is the *claim* — seconds since the
    -- epoch — that `sessions.authenticated_at` is also spelled out of.
    add column authenticated_at timestamptz,
    add column acr              text,
    -- Ordered, like `sessions.amr`: RFC 8176 values in the order the person
    -- proved them. Not null with an empty default, so "no methods recorded"
    -- and "no authentication at all" are not the same value.
    add column amr              text[] not null default '{}';

-- The three are one fact and are written together. A row with an `acr` or an
-- `amr` but no instant is a half-written authentication, and the reader would
-- have to guess whether it may assert it — `GrantRecord::validate` refuses
-- one, and this keeps the database from producing what the model refuses.
alter table grants
    add constraint grants_authentication_is_whole
    check (authenticated_at is not null
           or (acr is null and cardinality(amr) = 0));
