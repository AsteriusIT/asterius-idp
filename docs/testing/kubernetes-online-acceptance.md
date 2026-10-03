# Controlled direct online Kubernetes acceptance

Candidate372a51de with binary SHA256
11f0d89427097dd2d4797311abea5e0fb26b973838fa3bebb70e531f453785ca
and production Go adapter0ae022c8 passed15 control groups on disposable kind1.35.
The sanitized JSON records control names and limits. Reproduce with the dedicated
runner; Rust compilation is outside its scope.

Warm native exact-grant revocation took10.289 seconds with inner webhook TTL0s
and Kubernetes' default outer positive TTL10s. This observed path does not prove
the40-second source-derived delayed-lookup/cache bound. Source-route lock
contention refused in the2.5–4.5-second assertion interval around its3-second
local deadline; all lock/DB availability changes were restricted to the nonce DB.
All owned clusters/containers/listeners/databases were confirmed absent afterward.

Earlier attempts found and corrected two production defects: public SID versus
private lookup digest confusion (including separately fixed atomic grant rotation
ast-kq2m), and missing empty group_ids for humans without memberships. Actual
native request /review?timeout=30s was captured with its token redacted; the Go
adapter now accepts that exact transport query without extending its local
3-second deadline. A diagnostic relay was removed before the final direct run.
A fixture error presenting two client-auth methods on second CC mint was fixed;
production rejected it correctly. No production authentication was relaxed.

Historical session/proof data were seeded explicitly; real new proof for rotation
was password, not a fresh passkey or UV ceremony. Multiple replicas, delayed TLS
wire-response injection and final-signature/storage races are unmeasured in this
checkpoint. Human normative review still gates delivery, main merge and enabling.
