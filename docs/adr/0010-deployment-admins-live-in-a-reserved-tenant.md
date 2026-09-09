# ADR-0010: Deployment admins are users of a reserved tenant

- **Status:** Accepted
- **Date:** 2026-09-09
- **Bead:** ast-31x
- **Deciders:** Quentin RODIC
- **Refines:** [ADR-0009](0009-the-admin-console-is-a-first-party-same-origin-app.md)

## Context

[ADR-0009](0009-the-admin-console-is-a-first-party-same-origin-app.md) settles
how the console authenticates: the same `__Host-asterius_session` cookie as the
rest of the first-party surface, because the login flow is the only thing that
produces a `Session`. It leaves one question open, and `ast-1cj` — seeding an
admin so `docker compose up` gives a working deployment — cannot move until it
is answered.

Two facts in the tree decide it.

`Session` carries `tenant: TenantId`, and the field is not optional. Every
query that reads a session is scoped by that tenant, and the sessions table,
the grants table and the audit trail all inherit the scoping from it.

`users` is keyed `(tenant_id, user_id)` with `references tenants (tenant_id) on
delete cascade`. A user has no existence apart from a tenant, and removing a
tenant removes its users.

An admin who administers *one tenant* therefore has a natural home already. An
admin who administers *the deployment* — who creates the first tenant, who can
see across tenants — does not.

## Decision

Deployment admins are **users of a reserved tenant**, marked as such in the
`tenants` row and protected from deletion. Authority is carried by a **role on
the user**, whose scope is either one tenant or the deployment; the reserved
tenant is where deployment-scoped roles are allowed to live, not a second
authentication mechanism.

Nothing about `Session` changes. `Session::tenant` stays non-optional, every
tenant-scoped query keeps its invariant, and the login flow that produces a
session is the one that already exists. The reserved tenant is a real tenant
row: it has an issuer, it is subject to the same schema constraints, and it is
readable by the same code as any other.

Two protections are part of this decision, not follow-up work:

- The reserved tenant **cannot be deleted**, enforced in the database rather
  than by application discipline. The cascade that makes an ordinary tenant's
  users disappear with it is exactly what must not reach a deployment admin.
- A deployment-scoped role **cannot be granted to a user outside** the reserved
  tenant. Otherwise an ordinary tenant becomes implicitly privileged, and the
  authority stops being readable from the data.

The alternatives considered:

- **A deployment-scoped role on any user, with no reserved tenant.** Cheapest
  in schema terms and rejected on two counts. Deleting the host tenant deletes
  the deployment admin by cascade — a routine operation removing the ability to
  administer the deployment. And an ordinary tenant silently becomes
  privileged: nothing in the data says which tenant matters, so the answer
  lives only in whoever remembers.

- **A separate principal type outside the tenant model.** Conceptually the
  cleanest: a deployment admin genuinely is not a tenant's user. Rejected on
  cost. It makes `Session::tenant` optional, and that option has to be handled
  at every point that reads a session — each one a place where the `None` arm
  can be written wrong, in code whose current invariant is that a session
  always has a tenant. The reserved tenant buys the same separation with a row
  instead of a type.

## Consequences

`ast-1cj` can proceed: seeding an admin means creating the reserved tenant, a
user in it, and a deployment-scoped role, and `scripts/smoke-test.sh` gains an
assertion that the seeded admin exists and can authenticate.

`AuditActor::Admin(String)` already exists; under this decision the string it
carries is a user identifier, not a client identifier.

The reserved tenant is discoverable by anyone who can list tenants. That is
deliberate — an admin surface that hides where its authority lives is harder to
audit, not safer — but it means the tenant's login surface deserves the same
scrutiny as any other, and more attention to authenticator strength: `Session`
already carries `acr` and `amr`, so requiring a phishing-resistant authenticator
for deployment-scoped roles is available later without a schema change.
