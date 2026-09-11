-- Email verification (ast-vae).
--
-- The sibling of `recovery_tokens` (0015), and deliberately a second table
-- rather than a `purpose` column on the first. The two tokens are worth
-- different things: one resets a credential, one asserts OIDC Core §5.1's
-- `email_verified` and nothing else. Sharing a table would mean sharing a
-- lookup, and a single `spend` that could return either would be one missing
-- predicate away from letting a confirmation link be presented where a reset
-- link is expected — which is account takeover by way of a sign-up form.
--
-- The messages go in the existing transactional `outbox`, like recovery's, so
-- there is no window in which a token is live and the message announcing it
-- was lost (ADR-0001).
--
-- No plaintext token column. A copy of this database yields digests, which are
-- not links.
create table email_verification_tokens (
    tenant_id       text        not null,
    -- The lookup key. `spend` matches on this alone within the tenant, which
    -- is what lets the whole check be one statement.
    token_hash      text        not null,
    user_id         uuid        not null,
    -- The address the message went to, as the account recorded it at that
    -- moment. This is the fact the token proves, and it is stored rather than
    -- recomputed at spend time because the account's address can move in
    -- between: sign up as attacker@evil.test, ask for a link, change the
    -- address to victim@bank.test, follow the link. Without this column the
    -- flag would land on a mailbox nobody proved. The handler compares it
    -- against the current address before writing `users.email_verified`.
    address         text        not null,
    issued_at       timestamptz not null,
    expires_at      timestamptz not null,
    -- Non-null means no longer usable, whichever way it stopped being usable.
    -- The reason sits beside it so an operator can tell a completed
    -- confirmation from a link retired by an address change — a distinction
    -- the handler deliberately cannot make visible to a browser.
    consumed_at     timestamptz,
    consumed_reason text        check (consumed_reason in ('spent', 'superseded', 'address_change')),

    primary key (tenant_id, token_hash),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    constraint email_verification_expiry_after_issue check (expires_at > issued_at),
    constraint email_verification_reason_with_consumption
        check ((consumed_at is null) = (consumed_reason is null))
);

-- The two writes that are not by hash — superseding a user's earlier tokens at
-- issue, and retiring them all when the address changes — both scan by user.
-- The retention sweep deletes by `expires_at`, which is the third column.
create index email_verification_tokens_by_user
    on email_verification_tokens (tenant_id, user_id, expires_at);
