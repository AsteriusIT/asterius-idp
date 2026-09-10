-- Purging a compromised key: destroying the material, which retiring does not.
--
-- `retire` takes a key out of the published JWK Set. The row keeps its
-- encrypted private half, because a retired key is one whose time simply came:
-- OIDC Core §10.1.1 rotation, nothing wrong with the key. A *compromised* key
-- is a different fact and needs a different operation. FAPI 2.0 SP §6.8 is
-- about shrinking "the time window in which a compromised key can be used", and
-- a window that a database dump can reopen months later has not been shut.
--
-- So a purge does two things this schema has to allow:
--
-- 1. **The ciphertext goes.** Not the row: the `kid` is an RFC 7638 thumbprint
--    and must never be handed out twice, and an incident review has to be able
--    to see that the key existed, when it signed, and when it was destroyed.
--    Only the three envelope columns are emptied, which is why they become
--    nullable here. Emptying them is what makes a stolen backup taken *after*
--    the purge carry nothing to forge with — the KEK is a single key held
--    outside the database and shared by every row, so there is no per-key
--    handle a KMS could destroy instead. In this deployment shape, erasing the
--    ciphertext *is* the destruction of the material.
--
-- 2. **The state says so, terminally.** `purged` is added to the state machine
--    rather than reusing `retired` with a flag, because every reader of this
--    table matches on the state, and a reader that has not been taught about a
--    flag would keep treating the row as an ordinary retired key. The new state
--    makes every one of those readers a compile error until it has an answer.
--
-- `purged` is terminal: no statement moves a key out of it, and no key material
-- can be put back, so nothing is lost by that being unenforceable in SQL — the
-- envelope constraint below refuses a `purged` row that carries material at
-- all.
alter table signing_keys
    add column purged_at timestamptz;

comment on column signing_keys.purged_at is
    'When the private material was destroyed in response to a compromise. '
    'Distinct from retired_at, which only says the key left the JWK Set.';

-- The envelope columns are absent exactly when the key has been purged.
alter table signing_keys
    alter column private_key_ciphertext drop not null,
    alter column private_key_nonce      drop not null,
    alter column kek_id                 drop not null;

alter table signing_keys
    add constraint signing_keys_material_is_absent_only_when_purged check (
        case when state = 'purged'
             then private_key_ciphertext is null
                  and private_key_nonce is null
                  and kek_id is null
             else private_key_ciphertext is not null
                  and private_key_nonce is not null
                  and kek_id is not null
        end
    );

alter table signing_keys
    drop constraint signing_keys_state_check;

alter table signing_keys
    add constraint signing_keys_state_check
        check (state in ('pending', 'active', 'retiring', 'retired', 'purged'));

-- The timestamps remain the state machine's own account of itself. A purged key
-- has left the JWK Set — a purge from `retiring` cuts the grace period short —
-- so `retired_at` is required as well as `purged_at`, and no key that is still
-- in service may carry a `purged_at`.
alter table signing_keys
    drop constraint signing_keys_timestamps_follow_the_state;

alter table signing_keys
    add constraint signing_keys_timestamps_follow_the_state check (
        case state
            when 'pending'  then activated_at is null
                                 and retiring_at is null and retired_at is null
                                 and purged_at is null
            when 'active'   then activated_at is not null
                                 and retiring_at is null and retired_at is null
                                 and purged_at is null
            when 'retiring' then activated_at is not null
                                 and retiring_at is not null and retired_at is null
                                 and purged_at is null
            -- A key can be retired straight out of `pending` when it is
            -- destroyed before it ever signs, so only the final stamp is
            -- required here.
            when 'retired'  then retired_at is not null and purged_at is null
            when 'purged'   then retired_at is not null and purged_at is not null
        end
    );
