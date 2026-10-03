# Temporary application privileges

The tenant console’s **Temporary privileges** screen configures an existing
client role, registered resource, exact resource permissions, maximum duration
and independent approvers. The resource owner needs `admin.app_roles:write`;
looking up account usernames also needs `admin.users:read`. These administrative
commands require the first-party console session and CSRF protection. An OAuth
client carrying the same administrative scopes cannot configure this authority.

New policies are disabled. Record eligibility with an exclusive end time, then
enable the policy after checking the displayed role, resource and permissions.
Eligibility permits a request; it does not assign the role. The account’s
**My requests and approvals** page submits a reason and bounded duration,
shows the immutable request and decision deadline, and permits independent
approval, rejection, cancellation and withdrawal. Requesters, owner-policy
editors and eligibility editors cannot approve the request enabled by their
own action. The approver must belong to the configured approver set.

Requests expire after five minutes. Activation defaults to at most fifteen
minutes, can never exceed one hour, and ends earlier if eligibility expires.
The exclusive activation deadline cannot be extended. A renewal requires a
new reason, current eligibility and another independent approval. The background
worker records expiration in bounded, idempotent batches; live authority checks
compare the database clock and do not wait for that worker.

## Assurance and current authority

Submission, approval and privileged token issuance use the configured tenant
ACR ladder and server-owned local authentication provenance. Freshness is
limited to 120 seconds. The age of the oldest proof required by the assigned
class is retained across cumulative step-up; a newer password cannot refresh
an older passkey. Legacy sessions and federated assertions without verified
local proof cannot supply this freshness. Reauthentication repairs authentication
only and never restarts an activation’s lifetime.

Temporary client roles are resolved for the exact human grant, client, resource
and permissions. Actual resource permissions must exactly match the immutable
approval; a token asking for additional permissions receives no temporary role.
OIDC identity and grant-management protocol scopes do not supply resource
permission. Delegated agents, Agent Tasks and unrelated resources cannot
borrow an activation. Resources must enforce both the role and the token’s
resource permissions for the requested operation. Ordinary standing
role assignments retain their existing authority. A client role supplied solely
by temporary activation caps access-token expiry at its activation deadline.
An ID token is capped when the client is configured to release that role in its
ID token; personal identity claims alone do not acquire temporary authority.

The signing boundary rechecks current roles and their deadlines under the
same tenant publication fence used by authority changes, before and after any
asynchronous signing decorator. Temporary proof freshness is a separate private
evaluation bound and does not shorten the activation or issued JWT lifetime.
Policy evaluation and UserInfo remove temporary-only roles if an asynchronous
audit or directory read crosses an activation or proof deadline; independent
standing roles survive that clock update. Code redemption,
refresh and the supported policy boundary read current exact-grant authority.
UserInfo resolves current roles using the verified access token’s actual
audience and scopes, rather than the wider original grant.

## Withdrawal and resource enforcement

Removing eligibility, disabling a policy, changing its revision, deleting or
changing its catalogue bounds, disabling the owner or subject, and explicitly
revoking an activation remove temporary authority from subsequent online
decisions and privileged issuance. Re-enabling a subject or recreating a role
does not restore the earlier approval. Console conflicts retain the operator’s
context; refresh current records before making a new decision.

A previously issued self-contained JWT remains cryptographically valid until
its capped `exp`. Resources requiring immediate withdrawal must call the
supported online policy decision path, configure an active conditional
`access_evaluation` boundary that resolves roles from the verified human grant,
and enforce its result on each privileged action. Caller-supplied role
attributes and an unrelated service-account token do not prove a current
activation. That boundary needs a verified human token whose grant can be
resolved exactly; enable `grant_id_in_access_token` for the intended PDP client
profile when using this path. Missing or ambiguous grant context supplies no
temporary authority. Unguarded PDP evaluation continues to resolve standing
roles only. Offline validation does not promise immediate revocation. An unrelated
standing assignment can still authorize the same role; review standing and
temporary provenance separately before interpreting a withdrawal as loss of
all access.

The accepted lifecycle is specified in
[the activation ADR](adr/temporary-entitlement-activation.md). Kubernetes RBAC
projection and periodic access-review campaigns are separate integrations.
