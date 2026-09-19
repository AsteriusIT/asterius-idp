# Tenant session lifetimes

The scoped, audited `PUT /admin/api/v1/tenants/{tenant_id}/settings` accepts
`session_policy: {"idle_seconds": 3600, "absolute_seconds": 43200}`.
Both values are whole seconds, at least 60; idle cannot exceed absolute,
and absolute cannot exceed the browser cookie ceiling of 43200 seconds.
The console exposes these controls on Tenant settings → Sessions. The existing
settings-update authority and console CSRF protection apply. Invalid changes
are refused before the settings write; omitted policy preserves the stored one.
Token and refresh-token lifetimes remain independently configured.

Existing rows need no SQL backfill: an absent/null policy retains the previous
one-hour idle and twelve-hour absolute issuance defaults. A configured policy
is persisted in `tenants.settings.options.session_policy` and applied at the
PostgreSQL session boundary for both ordinary and reserved administrator tenants.
The reserved tenant's policy governs its console sessions even when an operator
switches to another tenant. This does not weaken passkey requirements or scope.

Each session lookup reads its own tenant's policy from PostgreSQL, so all replicas
see committed changes without a process-cache delay. Storage/validation errors
fail closed. A successful browser-cookie lookup counts as activity and renews its
idle deadline, capped by its original absolute expiry. Refresh-token and internal
lookups do not count as browser activity. Revoked, idle-expired or
absolutely expired sessions cannot renew or rotate. Rotation retains the original
creation time and absolute deadline; proving another factor cannot restart it.

A shorter current policy restricts existing sessions using `created_at` for
absolute expiry and `last_seen_at` for idle expiry. Longer settings never extend
an already issued absolute deadline. Policy expiry is an acceptance rule, not
permanent revocation: relaxing a policy can make a previously policy-restricted
session usable again only while its persisted deadlines remain live. Use session
revocation when access must remain withdrawn regardless of later policy changes.

The policy parser is exercised by the `tenant_settings` fuzz target. Domain and
admin tests cover boundaries, persistence and refusal; PostgreSQL tests cover
issuance, rotation, live policy changes and tenant separation. The latter are
ignored locally by default and run in CI's database checks.
