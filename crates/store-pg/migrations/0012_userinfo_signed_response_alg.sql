-- The algorithm a client's UserInfo response is signed with
-- (OIDC Registration §2, `ast-e89`).
--
-- Null is OIDC Core §5.3.2's default and not an algorithm: "the UserInfo
-- Claims are returned as a UTF-8 encoded JSON object". A column with a
-- not-null default would have turned signing on for every client already
-- registered, and `none` is deliberately not a value the check permits — the
-- absence of a signature is the absence of the member, never a name a client
-- can write into the algorithm field (RFC 8725 §3.1–3.2).
--
-- The allow-list is ADR-0003's, spelled the same way as the three columns
-- beside it, so a value the parser refuses cannot reach the row by another
-- door.
alter table clients
    add column userinfo_signed_response_alg text
        check (userinfo_signed_response_alg in ('EdDSA', 'ES256', 'PS256'));
