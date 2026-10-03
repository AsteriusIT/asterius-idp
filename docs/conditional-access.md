# Conditional access

Conditional scopes add a necessary authorization check for named registered
clients and enforcement boundaries. They never replace FAPI authentication,
DPoP, consent, grant ownership, scopes, audiences or explicit-deny precedence.
The model and source contract are in
[the trusted-context ADR](adr/trusted-conditional-access-context.md).

The token signer composes task/lineage and policy-publication locks. Key
preparation and shared signing admission precede those locks. Configure
`database.max_connections` to at least **3**: the composed signer needs room for
task and publication transactions plus current-source reads and audit writes.
Insufficient capacity and a five-second admission timeout fail closed as an
operational error. Admission is shared across tenant/request clones and bounds
concurrent signing to `(max_connections - 1) / 2`; it prevents signers from
occupying their own entire connection pool. Database outages or blocked writers
remain operational failures, never permission fallbacks.

## Classification and publication

Application sensitivity is administrative client configuration, separate from
Dynamic Client Registration and descriptive PEP resource properties.
`GET /admin/api/v1/clients/{client_id}/conditional-access` returns
`{"sensitivity":null,"revision":null}` until configured. An administrator with
`admin.clients:write` can PUT exactly:

```json
{"sensitivity":"critical","expected_revision":null}
```

Both keys are required. Later changes name the returned UUID revision;
stale/absent expectations return 409. Setting sensitivity to null removes its
trusted value while retaining a new revision. Client deletion/recreation cannot
reuse the old revision. GET requires `admin.clients:read`.

A policy containing scopes, or replacing a policy that already contains them,
requires an explicit publication expectation. For first publication, PUT
`/admin/api/v1/policies` with `If-None-Match: *`. For replacement, read its
canonical `revision` and send `If-Match: "sha256:<digest>"`. The quoted value is
required; malformed or duplicate expectations return 400 and stale/missing
expectations return 409. Omission of previously active scopes is still a
conditional change. DELETE cannot silently remove a scoped policy: publish a
reviewed replacement using its current revision. Existing unscoped writes keep
their original compatibility behavior. Registered-client and supported-remedy
checks also cover direct SQL and declarative publication.

```json
{
  "version": 1,
  "rules": [{"id": "baseline", "effect": "permit"}],
  "conditional_scopes": [{
    "id": "sensitive-application",
    "mode": "report_only",
    "clients": ["registered-client-id"],
    "actions": ["authorize", "authorization_code", "refresh_token"],
    "required_facts": ["application_sensitivity"],
    "assurance_remedy": "phr",
    "rules": [{
      "id": "fresh-strong-user",
      "effect": "permit",
      "subject_type": "user",
      "when": {"all": [
        {"application_sensitivity": "critical"},
        {"acr_at_least": "phr"},
        {"authentication_age_at_most": 300}
      ]}
    }]
  }]
}
```

`mode` is mandatory. Report-only records the conditional outcome and leaves the
existing boundary result intact; it cannot turn another denial into a permit.
Active mode requires both existing permission and the conditional permission.
Activate only through a reviewed revision-checked replacement. Scope client and
action pairs cannot overlap; limits are 64 scopes, 128 total rules and the
existing 64 KiB document bound. Conditions are closed typed data.

Supported enforcement actions are `authorize`, `authorization_code`,
`refresh_token`, `device_code`, `ciba`, `token_exchange`, `client_credentials`,
`jwt_bearer` and `access_evaluation`. ID-JAG minting uses `token_exchange` and its
redemption uses `jwt_bearer`. An AuthZEN resource action such as `read` is
separate from its `access_evaluation` boundary. The application at that boundary
is the cryptographically authenticated PEP client, rather than a submitted
resource name.

## Facts and freshness

Required facts combine explicit scope requirements with references in every
selector-applicable condition, including `not` and `any`. Unknown values cannot
be bypassed by negation, alternatives or unconditional permit rules. A rule
whose subject/resource/action selector does not apply adds no condition-derived
requirements to that question. Missing required evidence denies active scopes.

| Fact | Authority |
| --- | --- |
| Assurance | Exact server-owned assurance proof, matched to the current ACR ladder revision and its frozen verified factors |
| Authentication age | Oldest factor needed for the proven class; refresh, token `iat` and weaker cumulative step-up do not reset it |
| Application sensitivity | Current administrative classification for the exact client |
| Network zone | This request's direct peer, or a valid operator-trusted proxy chain, matched to configured CIDRs |
| Groups, roles, grants | Current tenant repositories for the relevant subject; directory failures refuse the evaluation |
| Device compliance | Dedicated enrolled-device adapter; until activated, this source is explicitly unavailable |

Availability is `known`, `absent`, `stale`, `unavailable` or `invalid`. Facts
carry bounded source/observation/expiry metadata, with a 30-second validity
window for this request's directory/configuration observations. The final check
advances the clock after lock and audit waits, without rewriting observation or
original authentication times. Future authentication timestamps are invalid.
An agent or delegated actor cannot borrow a human parent's assurance. AuthZEN
uses an exact signed public grant link, or the signed task/JTI/revision private
link after full token verification, sender, audience, revocation and scope
checks; it never selects an unrelated elevated grant.

Assurance provenance is separate from public OIDC `auth_time` and cumulative
`amr`. A fresh password can advance the public authentication time while a
class that still depends on an older passkey retains that passkey's original
proof age. A complete fresh proof replaces the age; a multi-factor combination
retains the earliest required factor. The exact ACR policy digest and verified
factor set are frozen with the proof. Changing the ladder, missing legacy
provenance or an inconsistent future timestamp makes scoped assurance/age
unavailable or invalid until a supported fresh authentication completes.
A federated callback establishes a verified upstream assertion, not the age of
the upstream human sign-in ([OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)). Federated/remembered-session methods cannot supply
this local freshness proof; they require a supported local ceremony.
Existing records receive no inferred proof during migration. Grants retain
original provenance after browser-session cleanup; refresh and exchange copy
that evidence without renewing its clock. No provenance fields are public JWT
claims. Ordinary unscoped cumulative ACR/AMR behavior remains compatible.

Define network zones in the scope, for example
`"network_zones":{"office":["192.0.2.0/24","2001:db8::/32"]}`. Forwarded headers
from an untrusted immediate peer are ignored. Malformed, ambiguous or
oversized trusted-proxy chains produce invalid origin rather than falling back
to a potentially permitting address. A browser login's address does not become
an address fact for later refresh or exchange. Caller properties in reserved
`trusted`/`trusted.*`/`asterius.trusted.*` namespaces are rejected.

## Step-up and already issued tokens

Interactive step-up is a denied outcome with a hypothetical remedy. Only fresh
supported authentication that would satisfy the whole scope can produce that
remedy; device/network hard denials cannot. Persisted requirements bind the
original pushed client, `authorize` action and policy revision. Existing
essential ACR requirements intersect with the remedy, and the stricter age
bound wins. Verified completion rechecks the current policy before creating or
amending the grant. `prompt=none` cannot create interaction or bypass a required
step-up. Conditional fresh reauthentication counts only methods proved in the
current ceremony; it cannot refresh an old passkey proof by entering a password.
Custom combined-factor ladders requiring several fresh ceremonies are refused
until the server can record freshness for each factor. Noninteractive grants return a generic refusal without sensitive
policy/directory details.

Publication fences cover first insert, update and deletion: a prepared
signature observes one complete policy publication. Every issuance boundary,
including code, refresh, device, CIBA, exchange and specialized workload/native
paths, receives the same conditional guard; final signing checks the actual
narrowed token scopes and audiences. Task binding and server-owned implicit
resources continue through every signer decorator. Authorization completion
checks its current snapshot before creating the grant; it does not lock policy
publication until code redemption. Configure both `authorize` and
`authorization_code` when the policy must also govern later code redemption.

Changing policy does not recall an offline JWT already accepted by a resource
server. Online AuthZEN evaluates current policy, and existing revocation/SSF
integration retains its own configured delivery and enforcement behavior.
Offline acceptance ends at the token's expiry; this feature makes no instant
withdrawal claim for those resources. Conditional audit diagnostics record
policy/source revisions and fact availability rather than raw IPs, device IDs,
user attributes or policy literals. Administrative simulation and historical
explanations remain separate from permission and token issuance.

## Verification

`./scripts/verify.sh 'test(conditional) or test(forwarded) or test(agent_tasks) or binary(authorization_code) or binary(refresh) or binary(token_exchange)'`
runs targeted Rust checks with the repository audits. The ignored
`conditional_access` PostgreSQL integration test belongs to CI.
`ASTERIUS_BIN=/path/to/verified/asterius ./scripts/conditional-access-acceptance.sh`
creates and removes its own local database and TLS services for FAPI/DPoP,
classification/publication CAS, unavailable-device NOT/ANY, report-only, actual
connection zones, publication/signature races, current AuthZEN policy and
original refresh-authentication-age controls. Its seeded refresh authentication
is a controlled input, not evidence of a live human login.

The local verification record is [conditional-access-evidence.json](testing/conditional-access-evidence.json).
It includes actual FAPI/DPoP issuance and AuthZEN controls, concurrent signing,
publication races, and real Chromium password/WebAuthn authorization and token
verification. The seeded refresh-age input and uninstrumented fuzz smoke are
identified separately.
