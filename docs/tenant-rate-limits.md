# Tenant rate limits

An operator with `admin.tenants:write` can lower abuse-control maxima in
**Tenant settings → Rate limits**, or with `PUT /admin/api/v1/tenants/{id}/settings`.
The settings GET requires `admin.tenants:read`; the server rechecks the named
tenant, including when a deployment administrator operates across workspaces.

```json
{
  "authorization_code_lifetime_seconds": 60,
  "access_token_lifetime_seconds": 300,
  "disabled_features": [],
  "rate_limits": {
    "login": { "per_account": 5, "per_address": 50 },
    "token": { "per_client": 100, "per_address": 20 },
    "backchannel": { "per_subject": 2 }
  }
}
```

Every maximum must be a positive integer no larger than the running deployment's
corresponding maximum. Unsupported groups, buckets, window changes, zero,
fractional and oversized values are refused before any settings are written.
Omitting `rate_limits` preserves existing overrides. Sending `{}` restores all
deployment defaults; omitting a bucket from a supplied object inherits that
bucket. A successful update records `rate_limits.before` and `.after` in the
administrative audit event. Existing CSRF, authority and audit controls apply.

GET returns the stored `rate_limits`, the actual deployment `rate_limit_bounds`,
and `effective_rate_limits`. The last two have the same group/bucket layout,
with `{ "max": 100, "window_seconds": 60 }` in each bucket. The console uses
these values for guidance rather than copying deployment defaults.

By default tenants inherit `[login]` and `[limits]` from the
[generated configuration reference](configuration.md). Login defaults are 10
failures per account and 100 per address in 900 seconds. Protocol maxima vary
by endpoint and use the deployment's configured window. Tenant overrides never
change windows, bucket names or stored counts; after a deployment tightens its
limits the effective maximum is the smaller of the stored override and current
deployment ceiling. Restoring inheritance also preserves counts.

| Group | Coverage | Configurable buckets |
| --- | --- | --- |
| `login` | Password/passkey sign-in and recovery paths using LoginThrottle | `per_address`, `per_account` |
| `registration` | Dynamic registration | `per_address` |
| `client_configuration` | RFC 7592 registration management | `per_address` |
| `par` | Pushed authorization requests | `per_address`, `per_client` |
| `token` | Token endpoint, including device/CIBA polling | `per_address`, `per_client` |
| `device_authorization` | Device authorization initiation | `per_address`, `per_client` |
| `userinfo` | UserInfo | `per_address` |
| `introspection` | Token introspection | `per_address`, `per_client` |
| `revocation` | Token revocation | `per_address`, `per_client` |
| `ssf_subjects` | SSF add/remove-subject | `per_address`, `per_client` |
| `backchannel` | CIBA initiation | `per_address`, `per_client`, `per_subject` |
| `access_evaluation` | Authorization API evaluation | `per_address`, `per_client` |

The fixed device-code guessing, approvals-decision, CIBA pending-request and
admin API budgets remain deployment controls; this editor does not expose them.
Disabled endpoints remain disabled regardless of their displayed budgets.

All replicas use PostgreSQL `rate_limits` counters keyed by tenant, bucket and
an epoch-aligned whole-second window boundary. Login counts failures; successful
protocol calls with a recognized authenticated client charge its client bucket,
and other requests charge the address bucket. CIBA subject limits bound requests
about the resolved person. Each replica reads tenant limiter settings directly
on its next check, bypassing the ordinary settings cache; a settings/counter
read failure refuses admission. Increment operations serialize in PostgreSQL.
Admission checks and response-time charging remain separate, so concurrent
in-flight requests can overshoot a maximum; these are existing abuse controls,
not a transactional reservation quota. Limit responses retain `429`,
`Retry-After`, existing metrics and throttle audit events.
