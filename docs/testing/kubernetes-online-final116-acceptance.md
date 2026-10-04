# Frozen 116-migration online Kubernetes acceptance

On 2026-10-04, source `fd2c8ae1a388f3dcaadf31b3e38a6281ae0d187f`
and normal CLI binary SHA256
`86f5fdc9eb82a795a0ac83a437815f6f248c89976b88ffbbdef7ad549b8136e4`
passed all 18 owned Kubernetes acceptance groups. The accompanying JSON records
aggregate controls, measured timings and exact runner file hashes. The compiled
production Go adapters came from that same frozen source. Reproduce with
`ASTERIUS_BIN=/path/to/verified/binary bash scripts/kubernetes-online/run.sh`.

The disposable cluster used the already cached Kubernetes 1.35.0 image, two
production mTLS adapters, an opaque TLS connection selector and a nonce database
on the approved local acceptance PostgreSQL. It exercised real PAR, PKCE,
private-key JWT, DPoP, code redemption, refresh digest registration, password
step-up/session rotation and original-grant refresh. Initial browser sessions
and historical assurance were controlled seeds; no fresh WebAuthn ceremony is
claimed. Selected reviewer receipt revocation preserved an independent grant.

All native grant/group/user/logout, route authority, mTLS/SPKI, metadata
revision/restore, three-second table-lock timeout and own-primary-DB outage
controls passed. Uncached identity continued through the second adapter after
terminating the first. With both adapters unavailable there was no native OIDC
fallback. Primary database replication was not exercised.

The opaque completed-response hold measured arrival at 25.002 seconds,
last native acceptance at 34.896 and denial at 35.193 from lookup start.
Revocation occurred at 3.521 seconds, yielding 31.672 seconds of residual
acceptance after revocation. A separate response held beyond the native timeout
was refused at 30.005 seconds; release at 35 seconds never created a late
positive cache entry. The ordinary warm-cache revocation control denied after
10.232 seconds. These measurements exercise the delayed lookup plus outer
10-second cache mechanism; they do not saturate the literal 40-second source
bound or establish a stronger bound without scheduling and clock-skew margins.
Final cryptographic/storage race injection was not part of this runtime fixture.

The launcher exited successfully and removed only its own cluster, container,
listeners, nonce database and private scratch files. Listener ports
9468/9470/9471/9472 were verified free; the shared cluster remained untouched.
Generated Python caches from the owned runs were removed. No Rust compilation,
image pull or shared deployment mutation occurred during this rerun.

Human normative delivery review remains pending. This verification does not
close that gate, authorize production enablement or constitute a main merge.
