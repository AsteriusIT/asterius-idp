# Governance findings

The console's **Governance findings** view reads current evidence and proposes
human review. The only report endpoint is
`GET /admin/api/v1/governance/findings`. It requires a first-party console
identity in the addressed tenant, `admin.governance:read`, and a currently active
local tenant/deployment administrator or `SecurityAuditor`. All actors must
belong to the exact addressed console realm. A reserved-realm administrator
cannot become an actor in another tenant through this endpoint. Responses use
`Cache-Control: no-store`; the store transaction is repeatable-read and read-only.
The report holds no cleanup command and performs no notification or mutation.

The `section` query selects `accounts` (default), `ownership`, `assignments`,
`temporary_entitlements`, or `administrative_roles`. `limit` defaults to 25 and
is bounded to 1–50. `after` is an opaque, versioned keyset cursor bound to the
tenant and section. Unknown or repeated query parameters and malformed,
cross-tenant or cross-section cursors are refused. A scan examines at most 100
source records. An empty page with a `next` cursor still requires continuation;
it does not mean the remaining tenant is clear. Each page states its own
observation time. It does not freeze future pages against intervening edits.
The console displays at most 250 findings before requiring a refresh/category
change. These bounds do not certify that every tenant finding was inspected.

## Evidence and fixed thresholds

Activity uses the latest retained, unrevoked session observation. An observation
older than **90 days** produces `no_recent_observed_activity`. An account older
than 90 days with no retained observation produces **`unknown_activity`**:
session retention, logout, API-only use and emergency accounts can all explain
the missing history. Neither value proves an upstream deletion. A disabled or
locked account independently produces `inactive_account`; that is local status,
not an inference about its upstream directory.

A SCIM mapping with a missing/inactive registered client produces
`disconnected_source`. Its explicit `deleted_at` produces `upstream_deleted`
separately. A LDAP ownership key absent from the current operator configuration
produces `disconnected_source`; `missing_since` records absence in an existing
complete bounded sync snapshot and produces `upstream_absent`. A configured
source or active SCIM client is only local registration evidence. The report
does not probe reachability, read bind credentials, infer feed health from a
client identifier reused after deletion, or label silence as upstream deletion.
Vendor external IDs, directory URLs, bind DNs and secrets are omitted.
More than 32 per-account source records is explicitly incomplete evidence.

No recorded provisioning source can be entirely legitimate for a local account.
When an account with administrative access has no recorded provisioning source,
the report flags it as a **possible local recovery account** if another finding
exists. This is a preservation warning, not proof of an emergency credential.
Confirm a working independent recovery path before any separately authorized
lifecycle change. Recovery accounts are not automatically disabled or removed.

Current ownership rows distinguish a missing/deleted owner, an inactive owner,
disabled review configuration, lack of active reviewers and a disappeared
standing assignment. Ownership existence does not grant access. A new assignment
without explicit ownership appears as `missing_ownership`.

Memberships older than **365 days** without a current recent applied-retain
review are candidates for `stale_membership`. Age alone does not establish
incorrect membership: stable project groups and externally managed groups can
be expected to live longer. The next step is confirmation with the owner or
source controller, not local deletion of managed membership.

Standing application-role assignments older than **90 days** without a current
recent applied-retain decision produce `unreviewed_privilege`. Current coverage
requires the exact standing row generation, ownership revision and complete
source context to match. Group membership/account changes, catalogue changes,
application status/metadata changes and assignment deletion/recreation can
invalidate historical review evidence. An oversized complete-context bound is
unknown coverage, never an abbreviated current fingerprint. Pending overdue
campaigns and unapplied decisions are reported separately.

Temporary entitlement findings inspect current owner and principal/catalogue
references. They do not treat historical approvals as standing review coverage
or infer token authority. Actual temporary privilege still depends on its exact
grant, independent approval, frozen assurance, resource permissions and exclusive
deadline. Administrative tenant/deployment role bindings older than 90 days are
separate review candidates: the standing-application review mechanism does not
apply or withdraw these roles. Existing administrator lifecycle authorization
and recovery protections remain mandatory.

## Acting on a finding

The response exposes public source identities/generations, current status,
observation timestamps, classified reasons and proposed review actions. It
contains no bearer token, session handle, private token JTI, credential or raw
directory inventory. A proposal never authorizes a mutation. Confirm current
evidence, assign an owner, start an independent review, or inspect a recorded
application result. Any removal uses its existing separately authorized
lifecycle command, current provenance checks and controller protections.

Verification passed: fmt, strict workspace clippy, 73 targeted tests, 113 fuzz
parser inventory/compile/lint checks, console TypeScript/Vite, and 18 actual HTTPS/
Chromium checks with a real password console login. Provenance and historical
review rows are controlled seeds, not live SCIM/LDAP feeds. The PostgreSQL
isolation regression remains CI-only. See the
[versioned evidence](testing/governance-findings-evidence.json).

To reproduce, build the console and the current Asterius binary, install the
`e2e` Node dependencies, then run `python3 scripts/governance-findings/acceptance.py`
with `ASTERIUS_BIN` and `ASTERIUS_ACCEPTANCE_DB_CONTAINER` naming the controlled
binary and PostgreSQL fixture on localhost:5433. Optional
`ASTERIUS_E2E_NODE_MODULES` selects existing read-only browser dependencies. The
runner owns ports 9480/9481 and a newly created disposable database; it cleans
its listener, database and private TLS material on exit.

Responses are capped at four MiB; an oversized report fails rather than implying complete partial evidence. Managed assignments include bounded current SCIM, LDAP, builder and controller flags. LDAP absence and a missing configured source remain separate findings; no controller-owned membership is removed by a proposal.
