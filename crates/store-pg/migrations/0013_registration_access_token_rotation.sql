-- The registration access token a rotation replaced, while its grace window
-- lasts (RFC 7592 §5, `ast-m9c.12`).
--
-- RFC 7592 §5 says the registration access token "MAY be rotated when the
-- developer or client does a read or update operation", and a tenant may now
-- take that MAY for updates. The reason it was declined until now is delivery:
-- this server issues no client secret (FAPI 2.0 SP §5.3.2.1), so the
-- registration access token is a client's only credential and there is no
-- re-issue path. A rotation whose `200` never reaches the client would strand
-- that client permanently — the state §5 tells implementers to avoid.
--
-- These two columns are the answer. For a bounded window after a rotation the
-- previous digest still authenticates, so the client's retry succeeds and is
-- handed the new token again. Nothing else about the row changes: the current
-- token stays in `registration_access_token_hash`, which is the column every
-- other statement and the revocation index already name.
--
-- The window is cover for a lost response, not a period of coexistence. Two
-- things keep it that way, and only one of them is here: the expiry below,
-- which the reader compares against, and the endpoint's rule that the first
-- request authenticated by the successor clears these columns immediately.
alter table clients
    add column previous_registration_access_token_hash bytea,
    add column previous_registration_access_token_expires_at timestamptz;

alter table clients
    -- Both or neither. A digest with no expiry is a second permanent
    -- credential for a client that is supposed to have exactly one, which is a
    -- worse outcome than the lockout the grace window exists to prevent; an
    -- expiry with no digest is a row nothing reads. Neither can exist.
    add constraint clients_previous_registration_access_token_is_complete
        check ((previous_registration_access_token_hash is null)
               = (previous_registration_access_token_expires_at is null)),
    -- A SHA-256 digest or nothing. A column of the wrong width would be
    -- compared against a truncated digest, and the comparison is the whole of
    -- this endpoint's authentication.
    add constraint clients_previous_registration_access_token_is_a_digest
        check (previous_registration_access_token_hash is null
               or length(previous_registration_access_token_hash) = 32);

-- Deliberately **no index** on the predecessor digest.
--
-- `clients_by_registration_access_token` exists because RFC 7592 §2.1's
-- "SHOULD be immediately revoked" is honoured on an unauthenticated request,
-- where a sequential scan would be the denial-of-service. That revocation
-- keeps looking at the current digest only, so a rotated-out token presented at
-- somebody else's configuration URL is refused but not burned. The trade is
-- deliberate: burning it too would mean a second indexed lookup on every
-- unauthenticated management request — doubling the work an anonymous caller
-- can compel — to shorten the life of a credential whose life is already capped
-- at minutes by the expiry above and ends at the successor's first use.
