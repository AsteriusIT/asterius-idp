# Online adapter failover and delayed encrypted response acceptance

Frozen372a51de binary SHA256
11f0d89427097dd2d4797311abea5e0fb26b973838fa3bebb70e531f453785ca
and Go0ae022c8 passed18 control groups against owned kind1.35.0. The committed
JSON contains only aggregate control names, measurements, source identifiers
and limits. Reproduce using `scripts/kubernetes-online/run.sh`; its own resources
are always cleaned, and no shared deployment or current kubeconfig is used.

Two unmodified production adapters9470/9471 independently verify the original
API-server certificate/SPKI and upstream FAPI reviewer. The own9472 connection
selector forwards opaque TLS bytes without decrypting/re-signing them or changing
HTTP. Killing the first replica did not prevent an uncached human token from
being authenticated by Kubernetes through the second. Both-replica outage later
refused an uncached native token. Primary-database replication was not exercised.

On a warmed mTLS channel, a fresh positive encrypted response was withheld
outside the completed production route. That route kept its3-second deadline.
After ciphertext was observed, the fixture waited3.5 seconds for completion,
revoked the exact human grant, and independently verified current source denial.
Release at25 seconds produced an already completed stale positive at25.002s.
Kubernetes last accepted that token at34.913s and denied it at35.214s from lookup
start; grant revocation occurred at3.521s, giving31.693s revocation-to-denial.
This demonstrates the upstream-lookup delay plus the later outer10-second cache,
not merely the adapter's local3-second deadline. The literal40-second edge was
not saturated; the conservative source bound remains40 seconds plus scheduling
and clock-skew margin.

A different freshly refreshed original-grant token was withheld beyond the
upstream lookup deadline. Native refusal occurred at30.004s. Releasing its
completed encrypted response at35s never populated a late positive cache entry;
repeated native checks remained denied after release. No cryptographic trust or
production timeout was weakened. A re-warmed healthy cache control denied the
ordinary revoked token after10.232s.

All initial15 lifecycle, exact reviewer-receipt, group, no-group human, user-disable,
logout, rotation/original-refresh, table-lock timeout and own-DB outage controls
also passed. Seeded historical methods and a real password proof established the
controlled rotation; no fresh WebAuthn/UV ceremony is claimed. Final signature or
storage race injection and multi-primary availability remain untested. Human
normative review still gates main delivery and production enablement.
