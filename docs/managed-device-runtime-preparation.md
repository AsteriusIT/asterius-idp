# Managed device runtime preparation

This is a candidate implementation for ast-dd1y.4.5 in its isolated branch.
Human normative review of [the selected trust contract](adr/managed-device-posture-source.md)
remains pending before delivery to main. The candidate exports typed ports,
mounts bounded management/relay and owner inspection routes, implements private
interaction/code proof transfer, and configures a dedicated authenticated proxy
TLS listener. Sources remain disabled by default. Source checkpoints composed by
the parent passed workspace checks/strict lint. The composed candidate at
`372a51de` passed 156 targeted Rust checks and all 115 fuzz target smoke checks.
The later composed candidate `d3f395c5`, including the final identity grant fence,
passed all 26 controlled HTTPS/browser checks with 115 embedded migrations. Its
retained binary SHA-256 is
`6c8cd8c81dc7ab3f144aba650321074bf19ece522e637a1295cf2cdbf3a1b95a`; see
[sanitized acceptance evidence](testing/managed-device-asterius-controlled.json).
Human review still gates delivery. This proves the controlled software PKI
profile; it does not prove live MDM interoperability or hardware attestation.

A subsequent source review found that original-code identity issuance and online
identity issuance needed a common final grant fence. The correction candidate
locks the current recipient client, then the complete bounded lineage from root
to exact claimed grant on the existing publication connection. It rejects tuple
changes, missing/cyclic/deeper-than-ten lineage, revocation and expiry after lock
waits. The minimum current lineage expiry caps the signed identity and is
rechecked after cryptography and online digest persistence. Separate consent/code
and exact-parent exchange preflight helpers never establish final issued authority.
A subsequent attempted timestamp pin exposed a normal-code regression: the
baseline database trigger updates `updated_at` even on first claim. Timestamps
also collide for authority amendments within one transaction. That attempted
correction is superseded by ast-dd1y.9's private UUID authority generation.
Migration0171 rotates the generation only for actual permission, authentication,
principal or actor changes; claim and expiry bookkeeping preserve it. An attested
same-public-session private lookup rotation preserves frozen authority, while
arbitrary session reassignment changes it.

Every derived child carries the immutable generation of its exact parent as
observed before derivation. Final publication validates each edge against the
locked current parent; it never substitutes a fresh parent generation for a
historical receipt. Legacy derived grants without a receipt fail closed for new
issuance and require reauthorization. Existing stateless credentials retain their
existing expiry/revocation contract; this migration does not claim retrospective
offline JWT withdrawal. No generation or receipt appears in public JWT claims.
The canonical lock order is tenant publication, sorted current clients, sorted
current human owners, then bounded root-to-leaf grants. An inactive ancestor
client or exact owner refuses new publication even when the leaf remains live.

Access issuance additionally carries a private held-authority value created only
after strict validation by the transaction-owning outer signer. It binds tenant,
issuer, exact grant ID/generation and the original minimum lineage expiry. The
outer transaction keeps publication, principal and lineage locks until signature
and commit. Inner conditional/device/role fact reads use that protected context
without obtaining the same tenant, client, user or root locks on a second
connection; otherwise a queued writer can cause the signer to wait on itself.
Identity issuance owns its full direct publication/lineage fence. Task access
forwards its complete issuance context rather than falling back to raw signing.
Specialized raw ID-JAG redemption remains a separate atomic protocol transition
and still needs an explicit publication-context handoff before candidate delivery.

These source corrections are not yet in the recorded 115-migration runtime
binary. Official metadata regeneration, targeted compilation/verification and a
fresh normal-code controlled runtime on the 116-migration candidate remain
required. Human normative review of the refined trust/compatibility contract
still gates delivery.

The corrected binary passed the full 26 normal HTTPS/browser controls, including
original-code identity issuance. That run does not claim to exercise withdrawal
between the access-token and identity signatures. Focused ignored PostgreSQL
regressions are supplied separately for CI; they verify real withdrawal waits,
withdrawal-wins refusal, fresh expiry after waits and bounded cycle rejection.
Those ignored tests have not been run locally. The composed final targeted gate
and human review remain separate delivery requirements.

The fixture performs real password and user-verified WebAuthn authentication,
FAPI private-key JWT/DPoP PAR/PKCE, exact interaction-to-code transfer, current
refresh/exchange/PDP possession, relay enrollment/posture and human source CRUD.
Initial primary source registration and offline refresh grants are seeded inputs.
Its stale observation check perturbs an owned database timestamp; it does not
claim to measure a real 300-second outage. Source/enrollment incarnation,
monotonic replay, tenant/user bounds, audit rollback, removal erasure and a
concurrent source publication/signature fence are exercised. The measured owner
removal-to-next-refusal interval was 0.367 seconds. Already-issued offline JWTs
remain bounded by their expiry and resource-server enforcement.

Source administration uses established exact-realm `ConsoleTenant` administrator
authority, current role admission, CSRF and existing session policy. A local
tenant administrator's password session is permitted under that existing policy;
this profile does not introduce governance's separate fresh-UV requirement.
The fixture also exercises source mutation from an actual UV passkey session.

The management API separates `admin.device_sources:read/write` and
`admin.devices:read/write` from relay-only `device.enrollments:write` and
`device.posture:write`. Tenant administrators register, inspect, disable and
revoke; they do not replace the source's device/user association with a browser
hint. Relay enrollment and posture calls must use the exact active registered
client in the routed tenant, a confidential client-credentials-only registration,
independent existing private-key JWT or OAuth mTLS authentication, and validated
sender-constrained tokens. User delegation, agent/task authority, workload
subjects, public clients and unrelated scoped clients cannot publish observations.

The relay JSON schema is closed. Posture batches carry profile
`managed-device-relay/v1`, source generation, and at most 32 observations in
8192 bytes. Each observation names a server-generated device UUID, enrollment
generation, strictly increasing nonnegative sequence, UTC Unix timestamps and
only managed/compliant/disk-encrypted/risk attributes. Duplicate device UUIDs
are refused before storage. The store revalidates time after acquiring its
locks and atomically rejects any wrong generation, stale sequence, removal or
invalid observation before writing the entire batch. A posture update never
enrolls, changes ownership or changes a certificate/application allow-list.

The source client, user and each allowed application must be current in the same
tenant. Enrollment stores only a lower-case SHA-256 leaf digest, never DER, a
private key, names, serials, vendor inventory or browser fingerprints. Renewing
a credential requires removal followed by fresh enrollment with a new UUID and
generation; the prior observation sequence/posture is erased. Ownership is pinned; transferring to another
user requires removal and a fresh server-generated UUID. Removed UUIDs cannot
be resurrected. Source disable/client replacement advances source generation;
re-enabling does not reactivate older associations automatically. Removed
generation tombstones retain only identifiers, generation and removal time for
30 days; removal erases posture, user/certificate references and application
bindings. Audit records contain identifiers/revisions/outcome categories.

Device CA files are a distinct operator configuration and a distinct anchor
instance from OAuth client CAs. The device adapter must require a CA anchor and
an end-entity leaf, reject self-issued/self-signed device leaves and duplicate
certificate headers, and check client-auth usage, chain and validity with the
existing rustls/aws-lc boundary. It reads a certificate only from the protected
connection of a configured trusted TLS-terminating proxy, whose configuration
removes caller headers and forwards the actually verified leaf. Parsing DER or
hashing it alone establishes no key possession. The TLS-termination trust
boundary follows [RFC 8705 §6.5](https://datatracker.ietf.org/doc/html/rfc8705#section-6.5);
the enrollment association is an application trust rule.

Authorization captures the exact server-owned interaction and verified
credential, then binds it to the independently authenticated local user and
application. The private binding contains source/enrollment generations,
device UUID, leaf digest, verification time, actual certificate expiry and
the dedicated anchor bundle revision. Anchor removal and restart cannot honor
an older proof merely because its 300-second time budget remains. An
authorization-code exchange may use only that original interaction's private
binding within its original deadline. Refresh, exchange and PDP requests need
matching verified evidence at their own boundary; absent evidence remains
absent, including privileged PDP clients without an authenticated local user.
No unrelated grant/session supplies the strongest available device. Device
proof does not change AMR/ACR, authenticate a user or register an OAuth client.

The current PostgreSQL interaction implementation replaces
`auth_requests.interaction_id_hash` whenever a browser begins an unfinished
pushed request. Its stable parent is `(tenant_id, request_uri_hash)`. The private
device sidecar must therefore record both digests and compare the current
interaction digest under the parent row lock; the stable parent alone cannot
confer authority on a later arrival. A replaced interaction clears its device
binding together with its existing session/challenge progress. A first-party
interaction has a different parent table and no OAuth application; it does not
supply a device proof to an OAuth authorization implicitly.

Completion currently spends the interaction before creating the grant and code.
Only the completion that won this existing atomic spend may transfer its exact
private proof. The transfer must be part of authorization-code insertion, not
an independently committed sidecar write. The code's digest is the proof's
parent identity and deletion cascades with that code. Grant Management merge
and replace can issue several different codes for the same grant, so a single
mutable proof keyed only by grant ID would let one authorization lend device
authority to another. Code redemption must return the original private binding
alongside the existing PKCE, redirect URI and DPoP binding and propagate it only
through that redemption's access issuance. A missing or invalid original
binding remains missing; it is never repaired by selecting another code,
session or grant. This requires a typed optional private field on `CodeBinding`
and preservation through `AccessIssuance` or an equally bounded request-local
issuance carrier. It does not add a public JWT claim or change code replay
revocation.

The final source/enrollment/latest-posture checks must use the same SQL
transaction as `PolicyPublicationFence`. Its source/enrollment/posture SHARE
locks last through signature, and a fresh clock recheck runs after audit waits.
There is no additional held-transaction-to-pool checkout for device resolution.
Mutations acquire source-client then source fences, user/application references
and deterministically ordered device rows; removal/disable use the same order.
The bounded signing admission and prepared key/decorator topology remain the
existing ones. The effective fact expiry is the earliest of the source expiry,
observation plus 300 seconds, actual certificate expiry and original proof
deadline. Unknown management/compliance is unavailable for a required device
fact; required-facts checks run before negation/alternative branches.

The five-second forward timestamp tolerance is an ingestion tolerance only.
An accepted observation whose source timestamp is still in the future cannot
produce a known fact until that timestamp is reached. This preserves the
existing `Fact::at` rule (`observed_at <= now < expires_at`) without resetting
the source timestamp to the receipt time or extending its freshness budget.

The controlled fixture will use separate valid device CAs, wrong-tenant CA,
valid/expired/self-signed/server-only leaves, a real TLS-verifying proxy and
independent relay FAPI credentials. It will cover tenant/user/application
binding, untrusted header spoofing, timestamps, replay, generation changes,
source/device removal, concurrent removal/update/signing, missing-fact negation
and measured online freshness. Source enrollment, user fixtures and keys are
controlled inputs; the fixture will explicitly disclose them. Existing offline
JWT expiry and source/proxy/software-key compromise limits remain as stated in
the trust contract. Runtime execution waits for review and the coordinated
verification slot.

## Prepared schema and runtime attachment points

The documentation-only [relay input schema](managed-device-relay.schema.json)
closes every object and describes the same structural vocabulary as the inert
unexported domain draft. JSON Schema validation is not source authentication,
TLS key possession or a replacement for locked generation/sequence/time checks.
The selected first profile bounds application identifiers to 256 bytes and
allow-lists to 64 entries; an empty list supplies no application authority.
The [fixture matrix](testing/managed-device-fixture-plan.json) enumerates 29
required positive/negative observations, all explicitly `not_run`.

Migration 0164 is reserved but not delivered or executed in this preparation.
The proposed persistence layout is:

| Record | Exact identity and stored facts | Mutation and removal behavior |
| --- | --- | --- |
| Source | Tenant + server UUID; exact registered relay client reference, source generation, revision, default-disabled flag | Disabling/replacing the source advances generation and invalidates all earlier associations; client deletion cannot leave an enabled source |
| Enrollment | Tenant + server UUID; source ID/generation, enrollment generation, local user reference, leaf SHA-256, bounded application references | Explicit renewal advances enrollment generation and clears latest posture/sequence; ownership transfer requires remove + fresh server UUID |
| Latest posture | Tenant + device UUID + enrollment generation; last sequence, original observation/source-expiry timestamps, four minimal attributes | One bounded atomic batch under source/enrollment locks; no updates can enroll or revive a removed device |
| Interaction proof | Tenant + `auth_requests.request_uri_hash`; current `interaction_id_hash`, exact source/enrollment/user/client binding, leaf digest, verification/certificate/proof expiry and device-anchor revision | Parent FK cascades on deletion; arrival replacement clears proof under the same parent row lock; no first-party interaction fallback |
| Code proof | Tenant + `authorization_codes.code_hash`; immutable original winning interaction proof and its deadline | Insert atomically with that exact code; redemption returns only its own private binding; parent deletion cascades; no grant-ID key |
| Removed-generation tombstone | Tenant + retired device UUID/generation + removal timestamp | Contains no posture, user, leaf digest or application references; retained for at most 30 days; absence still denies |

Both parent digests are existing `bytea` identities, never caller-provided
plaintext browser/request/code handles. They do not appear in management
inspection responses, token claims or audit events. Private code proof does not
widen the independent PKCE/redirect/client/DPoP requirements. Existing code
replay revocation remains authoritative and no extra redemption route is added.

`CodeBinding` currently has no device authority. Its future private optional
binding must come from the same database code read/spend that returns the
existing fields. `AccessIssuance` currently carries only the exact grant, grant
type and server-owned implicit resources; a future optional private request-local
device carrier must survive every prepared signer wrapper unchanged. It must
not be inferred from `grant_id`, signed `sub`, public token device claims or the
user's other active sessions. Construction belongs to verified ingress or the
exact validated code redemption, not a JSON deserializer accepting client hints.

`PolicyPublicationFence` currently keeps its SQL transaction private. Runtime
integration needs a narrowly scoped connection-based current-device resolver
on this fence, rather than another pool checkout or a public raw transaction.
The resolver must select source, enrollment, exact application binding and
latest posture under SHARE locks in deterministic order, validate the current
anchor revision, and return a private availability/expiry snapshot. Mutations
use compatible parent/source/client locks. After network/key preparation and
audit waits, pure-clock checks must retain the original proof deadline and
exclusive effective expiry; downstream asynchronous signing cannot reset either.
Current fact absence remains absence before mandatory required-fact evaluation.

The composed main `4066e08f` includes exact-grant frozen temporary-role proof
metadata and final UserInfo pruning. Device work must preserve that independent
proof and signer admission behavior; a device credential never upgrades
AMR/ACR or freshens those authentication-class proofs.


The isolated candidate now exports a private `DeviceBinding` carrier. It owns
exact tenant, user, application, interaction digest, source and enrollment
generations, leaf and current anchor fingerprints, certificate expiry and the
original proof deadline. `CodeBinding` owns an optional carrier; `AccessIssuance`
and `IdTokenParts` borrow it. Only the authorization-code handler forwards its
redeemed code carrier; refresh, exchanges and other handlers explicitly supply
`None`. `Signer::sign_identity_bound` is a compatible extension and task/prepared
wrappers preserve the supplied carrier. The conditional publication adapter must
implement the bound hook before device enforcement is enabled; its inherited
default intentionally retains old signing behavior and is not device enforcement.
This source checkpoint is uncompiled and unvalidated while the shared Rust slot
is occupied. No certificate verifier, interaction transfer, persistent sidecar,
mounted endpoint, or device policy enforcement is claimed by this checkpoint.


The next candidate checkpoint adds migration0164 and
`PgManagedDevices::resolve_for_grant_on(connection, tenant, grant, binding,
current_anchor)`. It never checks out another pool connection. It binds the
exact local grant user and client, current source authority/generation, current
enrollment generation, user/application liveness and allowlist, leaf and current
anchor fingerprint. It reads the database clock after locks and returns the
existing typed conditional `Fact`; its expiry is the minimum of posture
observation+300 seconds, source expiry, leaf expiry and original proof expiry.
Future observations, missing management/compliance and absent evidence cannot
become a known fact. Callers retain all locks through signing and recheck the
fact clock after awaited operations. The source HTTP adapter uses the existing
DPoP protected automation ingress; independent relay client authentication may
be private_key_jwt or OAuth mTLS, but a certificate-only API access token is not
accepted by that existing DPoP ingress. No sender constraint is substituted for
client authentication.

Code issuance and redemption candidate transactions now store and consume a
private sidecar beside the exact code digest. Redemption uses the existing
single-winner code spend and `DELETE RETURNING` of its sidecar in the same
transaction. The interaction-capture/transfer and removal writers are not yet
implemented; this remains incomplete source, without checks or runtime evidence.


The dedicated certificate candidate is implemented in
`crates/server/src/managed_devices.rs` and strict single-leaf transport in
`mtls::device_from_proxy_header`. It reuses the established aws-lc/webpki chain
verifier; [x509-parser0.18.1](https://docs.rs/x509-parser/0.18.1/x509_parser/certificate/struct.X509Certificate.html)
reads bounded DER constraints, explicit clientAuth and expiry, and never verifies
signatures with another provider. CA-only operator bundles are bounded to256KiB
and32 certificates; their sorted unique DER is length-prefixed and SHA256 hashed
with a device-profile domain separator to obtain the current stable trust
revision. It is not supplied by the browser or source. The proxy must perform
actual TLS client-key possession verification and strip the incoming field; the
adapter cannot prove those operator responsibilities from a forwarded header.
Startup configuration uses a separate `[managed_devices]` table and header,
requires `behind_proxy` when device roots exist, loads dedicated roots, emits a
private verified leaf extension and distributes the operator-derived revision
map through `ClientEndpoints` to each conditional gate. It depends on the
coordinated conditional setter in the parent's isolated candidate branch.
No compilation, TLS fixture or runtime acceptance has yet been run.


Source review found that the existing `BehindProxy` listener uses plain HTTP.
Trusted CIDR plus an ordinary forwarded public certificate therefore does not
establish the ADR's protected-hop possession boundary. The verifier now requires
an explicit private `VerifiedProxyHop` in addition to the trusted immediate IP;
no existing listener constructs it, so this checkpoint produces no managed
facts. A dedicated proxy client TLS handshake plus operator pin adapter is still
required. No configuration boolean, raw leaf digest or proxy header may create
that context. The upcoming candidate will document and test this transport
boundary before claiming certificate possession or runtime enforcement.


The protected-hop candidate now uses mandatory rustls TLS client authentication
against a separate bounded proxy CA bundle, followed by an exact operator proxy
client leaf SHA256 pin. Only the successful TLS accept adapter can construct
`VerifiedProxyHop`; ordinary HTTP, an unauthenticated handshake, a CA-valid
unlisted client or an expired proxy leaf cannot insert it. The edge must still
verify device key possession and strip caller fields. The selected profile uses
`[managed_devices.proxy_hop]` with backend certificate/key, dedicated proxy CA
and1..32 exact client leaf pins. The backend remains `behind_proxy` for issuer
and forwarded-origin semantics; it listens with TLS solely for the authenticated
hop. Existing listeners retain their previous transport configuration.
The current proof trust digest combines the dedicated tenant device CA bundle,
proxy CA bundle and sorted proxy pins. The verified leaf deadline is capped by
both device and proxy certificate expiry; certificate renewal or trust changes
cannot retain an old proof through a stale revision. The candidate is still
uncompiled and has no real handshake/edge fixture evidence yet.

## Candidate route and authority map

The routed tenant prefix precedes these paths. Source configuration is readable
under `admin.device_sources:read`; creation and revision-fenced update require
`admin.device_sources:write`. Human console tenant/deployment administrators can
write; an exact-tenant SecurityAuditor can read. Automation cannot manage trust.
`/admin/api/v1/device-sources` lists or creates bounded source metadata;
`/admin/api/v1/device-sources/{source_id}` updates a saved source and its enable
state. Every update advances the source generation; re-enable requires fresh
enrollment rather than reviving old associations.

`/admin/api/v1/devices` returns keyset pages of at most 100 current/minimal removed
records under `admin.devices:read`. Revision-fenced DELETE on
`/admin/api/v1/devices/{device_id}` requires `admin.devices:write`.
These responses omit the enrolled leaf digest, DER, private proof and receipt JTI.
The owner-only `/account/devices` JSON endpoint derives its account from the
usable browser session, never a query/body user. GET supplies a bounded page and
page-specific CSRF token; POST requires that token, a fresh authentication and
exact device revision before removal. It cannot inspect or remove another owner.

The separate source endpoints `/admin/api/v1/device-sources/{source_id}/enrollments`
and `/posture` accept only a same-tenant DPoP machine principal whose exact signed
JTI has a private successful **client_credentials** issuance receipt. Source/client
status, CC-only confidential registration, scopes, exact grant and receipt expiry
are checked again after lifecycle locks. A public `sub == client_id` shape alone
is insufficient. Independent private-key JWT or OAuth mTLS client authentication
continues to issue these sender-constrained credentials; no device leaf replaces
that authentication or enrolls a client.

## Current request and delegation phase

A refresh, ordinary OAuth exchange or PDP request receives a fresh server-owned
request digest and its own verified TLS device certificate; previous code,
session and grant possession are never copied. The private binding pins exact
`bound_grant_id` and, for exchange, explicit `request_parent`. Final signing and
PDP resolution require the authoritative claimed current exact grant under the
same publication connection, with current tenant/client/user/subject and expiry.

An ordinary local access-token exchange has a verified exact parent but its child
is provisional before the policy decision. Its early evaluation uses a distinct
preflight resolver that locks that explicit current parent and matches its user
and subject to the target child, plus the current source/enrollment and request
proof. This does not create or release issued authority. Final signing uses only
the strict persisted-child resolver. No parent search or provisional fallback is
permitted in a final decision. Specialized exchanges without this exact local
parent context and PDP tokens without an exact verified grant remain unavailable
for required device facts rather than borrowing another grant.

Configuration requires explicit dedicated proxy-hop client CA and exact proxy
leaf pins, a backend TLS certificate/key and trusted immediate proxy CIDRs. The
edge must verify the device handshake, strip incoming caller certificate fields,
and forward exactly the verified leaf over the authenticated pinned hop. Merely
configuring `behind_proxy` or knowing an IP does not prove device possession.
The current trust revision covers device CA plus proxy CA/pins, so removing an
anchor or changing a pinned proxy rejects older proofs after restart.

Active enrollment state is bounded per tenant. Expired interaction/code proof
sidecars and relay receipts are swept in bounded batches; removal immediately
erases user/leaf/app/posture attributes and deletes private proofs. Only minimal
removed UUID/generation/revision/timestamps remain for at most 30 days. Source
configuration is bounded trust state retained until explicit lifecycle removal.
