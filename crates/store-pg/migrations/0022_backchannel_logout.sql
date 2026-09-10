-- Where a relying party is told that a session ended, and whether it insists
-- on being told *which* session (OIDC Back-Channel Logout 1.0 §2.2,
-- `ast-o4u.2`).
--
-- Null `backchannel_logout_uri` is §2.2's own default: a client that
-- registered none is not a participant of back-channel logout and no logout
-- token is ever minted for it. It is deliberately not an empty string — the
-- absence of an endpoint is the absence of the member, and an empty
-- destination would be an outbox row that dead-letters on its first attempt.
--
-- The check is a floor under `ClientMetadata::validate`, which parses the
-- value as a `web` redirect URI and therefore refuses much more than this:
-- fragments, userinfo in the authority, loopback, and any spelling a URL
-- parser does not produce. What the constraint adds is the one rule that must
-- also hold for a row edited by hand in an incident, because this URL is
-- dereferenced by the server with a signed assertion in the body: it is
-- `https`. A row that became `http://` in a `psql` session would be a logout
-- token posted in clear.
--
-- `backchannel_logout_session_required` is not null with a `false` default,
-- which is §2.2's stated default — "If omitted, the default value is false" —
-- and which is the answer every client already registered gives.
alter table clients
    add column backchannel_logout_uri text
        check (backchannel_logout_uri is null
               or backchannel_logout_uri like 'https://%'),
    add column backchannel_logout_session_required boolean not null default false;
