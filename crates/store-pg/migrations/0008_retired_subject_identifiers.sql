-- Tombstones for subject identifiers (`ast-2vk.12`).
--
-- OIDC Core §8 defines a Subject Identifier as "a locally unique and **never
-- reassigned** identifier within the Issuer for the End-User". `subject_
-- identifiers` reserves one, and the unique index on `(tenant_id, subject)` is
-- what makes two users sharing a `sub` a refused write — but that row is `on
-- delete cascade` from `users`, so deleting an account gives the value back to
-- the pool. In practice nothing reissues it: the other input to the derivation
-- is a random UUID that is never reused. "In practice" is a weaker promise than
-- the one the specification makes, and a relying party that keyed its own
-- records on `sub` has no way to tell a reused identifier from a returning
-- person.
--
-- So the reservation outlives the reservation holder. This table has **no
-- foreign key at all** — not to `users`, whose cascade is the problem, and not
-- to `tenants` either: a tenant is an issuer, and deleting one and recreating
-- it under the same id would otherwise free every `sub` it ever issued.
--
-- **It stores the value, not the recipe.** Recomputing a retired pairwise `sub`
-- would mean keeping the sector, the local account id and reaching the salt
-- (ADR-0008) — that is, keeping exactly the user data the deletion was supposed
-- to remove, and paying a KEK operation to check a collision that never
-- happens. The emitted value is the whole of what has to be remembered, and it
-- is a 43-character digest that carries none of its inputs.
create table retired_subject_identifiers (
    tenant_id         text        not null,
    -- The `sub` as it was handed to a relying party.
    subject           text        not null,
    -- The sector it was issued for, kept for the incident report rather than
    -- for the check: '' is a public subject, as in `subject_identifiers`. It is
    -- not part of the key, because the guarantee is about the value alone.
    sector_identifier text        not null default '',
    retired_at        timestamptz not null default now(),

    primary key (tenant_id, subject)
);

-- A tombstone is written by the deletion it survives, so that no code path can
-- forget to write one: a cascade from `users`, a cascade from `tenants`, a
-- hand-typed `delete` in psql and an account deletion through the repository
-- all end at the same row-level trigger.
create function subject_identifiers_leave_a_tombstone() returns trigger language plpgsql as $$
begin
    insert into retired_subject_identifiers (tenant_id, subject, sector_identifier)
    values (old.tenant_id, old.subject, old.sector_identifier)
    on conflict (tenant_id, subject) do nothing;
    return old;
end;
$$;

create trigger subject_identifiers_tombstone after delete on subject_identifiers
    for each row execute function subject_identifiers_leave_a_tombstone();

-- The other half: a retired value can never be reserved again. The application
-- checks before it derives, so that the refusal is an explicit
-- `DomainError::Conflict` with an audit record rather than a constraint
-- violation — but the guarantee itself lives here, where a bulk import, a
-- migration or an adapter this schema has never heard of also runs into it.
--
-- A refusal and not a regeneration. Deriving something else and handing that
-- over is precisely the reassignment §8 rules out, and it would make the
-- pairwise calculation of §8.1 non-deterministic to boot; a `sub` that cannot
-- be minted is an authorization that fails, which is recoverable, whereas an
-- identifier issued twice is not.
create function subject_identifiers_are_never_reassigned() returns trigger language plpgsql as $$
begin
    if exists (select 1 from retired_subject_identifiers
                where tenant_id = new.tenant_id and subject = new.subject)
    then
        raise exception 'subject % was retired and is never reassigned', new.subject
            using errcode = 'unique_violation',
                  hint = 'OIDC Core section 8: a subject identifier is never reassigned; '
                         'this value was issued to an account that no longer exists';
    end if;
    return new;
end;
$$;

create trigger subject_identifiers_no_reassignment before insert or update on subject_identifiers
    for each row execute function subject_identifiers_are_never_reassigned();

-- A tombstone that can be removed or rewritten is not a tombstone, and unlike
-- `audit_events` there is no retention escape hatch: this table is `Kept` by
-- the policy for the same reason it refuses `DELETE` here. Like every other
-- trigger in this schema it is a defence against the application, an operator
-- with psql and a future migration, not against somebody who can already drop
-- it.
create function retired_subject_identifiers_are_permanent() returns trigger language plpgsql as $$
begin
    raise exception 'a retired subject identifier is permanent (attempted %)', tg_op
        using errcode = 'restrict_violation',
              hint = 'the row exists so that the value it names is never issued again '
                     '(OIDC Core section 8)';
end;
$$;

create trigger retired_subject_identifiers_no_update before update on retired_subject_identifiers
    for each statement execute function retired_subject_identifiers_are_permanent();
create trigger retired_subject_identifiers_no_delete before delete on retired_subject_identifiers
    for each statement execute function retired_subject_identifiers_are_permanent();
