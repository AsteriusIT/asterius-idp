# Managed device runtime preparation

This is source preparation for ast-dd1y.4.5. Human normative review of
[the selected trust contract](adr/managed-device-posture-source.md) remains
pending. The draft domain module is not exported, no device profile is enabled,
no endpoint is mounted, and its draft tests have not run. No interoperability or
hardware-attestation result is claimed.

The initial management API will separate `admin.device_sources:read/write` and
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
a credential requires an explicit enrollment-generation replacement and clears
its observation sequence/posture. Ownership is pinned; transferring to another
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
