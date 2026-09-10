-- Account recovery (ast-2vk.10).
--
-- One table. The messages themselves go in the existing transactional
-- `outbox` — the journal mail sender writes a row there in the same
-- transaction as the token it describes, which is the property that table was
-- added for (ADR-0001): there is no window in which a token is live and the
-- message announcing it was lost, or the reverse.
--
-- No plaintext token column anywhere. The token exists in the message and in
-- the request that spends it, and nowhere else; a copy of this database yields
-- digests, which are not links (NIST SP 800-63B §5.1.1.2, and OWASP's Forgot
-- Password Cheat Sheet says the same of reset tokens specifically).
create table recovery_tokens (
    tenant_id       text        not null,
    -- The lookup key. `spend` matches on this alone within the tenant, which
    -- is what lets the whole check be one statement.
    token_digest    text        not null,
    user_id         uuid        not null,
    issued_at       timestamptz not null,
    expires_at      timestamptz not null,
    -- Non-null means no longer usable, whichever way it stopped being usable.
    -- The reason sits beside it so an operator can tell a completed reset from
    -- a link cancelled by a credential change — a distinction the *handler*
    -- deliberately cannot make visible to a browser.
    consumed_at     timestamptz,
    consumed_reason text        check (consumed_reason in ('spent', 'superseded', 'credential_change')),

    primary key (tenant_id, token_digest),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    constraint recovery_tokens_expiry_after_issue check (expires_at > issued_at),
    constraint recovery_tokens_reason_with_consumption
        check ((consumed_at is null) = (consumed_reason is null))
);

-- The two writes that are not by digest — superseding a user's earlier tokens
-- at issue, and invalidating them all on a credential change — both scan by
-- user. The retention sweep deletes by `expires_at`, which is the third
-- column.
create index recovery_tokens_by_user
    on recovery_tokens (tenant_id, user_id, expires_at);
