# Independent SSF transmitter fixture

This disposable adapter composes the unmodified public transmitter API from
[IDFoundry/SSFgo](https://github.com/IDFoundry/SSFgo), pinned to commit
`ce2353e22367c276f8dada1dbf22ec9939a255b1` in `go.mod` and `go.sum`.
SSFgo owns metadata, stream CRUD/status, verification SET generation, poll/ACK,
subject selection and ES256 signing. The adapter supplies an ephemeral P-256
key, static operator bearer identity, audience and a local event trigger.
It does not use SSFgo's RS256-only CAEP conformance CLI, change Asterius's
algorithm boundary, or claim CAEP certification.

The publisher's library has no third-party dependencies and requires Go
1.26.6+. Prepare it with a suitable installed Go toolchain and private
`GOPATH`, `GOMODCACHE`, `GOCACHE`, `TMPDIR` directories when disk is scarce.
Set `GOTOOLCHAIN=local` to prevent implicit global toolchain downloads.
From this directory, run `go build -o <owned-path>/ssfgo-transmitter .`.
Python's `cryptography` is needed only for the independent signature smoke
check, not the transmitter.

Create a private regular bearer file (0600, at least 32 random characters).
Never put it in the diagram, source control, logs or evidence. Run:

```sh
<owned-path>/ssfgo-transmitter \
  -issuer https://<approved-public-host>:10000 \
  -audience https://<asterius-host>/t/<owned-tenant>/ssf/receiver \
  -bearer-file <private-file> \
  -bind 127.0.0.1:9485 -control 127.0.0.1:9486
```

Put only the protocol listener behind the approved HTTPS/Funnel route. Leave
the event control listener private. Both listeners reject non-loopback binds.
Preserve existing Tailscale Serve/Funnel routes; the example port is a proposal
whose availability must be checked. This fixture has no production durability:
keys, streams and queue are in memory and disappear at process exit.

Register the exact transmitter issuer and its advertised public JWKS as an
Asterius `ssf.receive` peer. Configure its operator bearer file,
`expected_audience` and `allow_all_subjects=true`; the fixture deliberately
advertises `default_subjects=ALL`. Use existing protected Asterius upstream
setup, verify, request-verification, poll and delete operations. Its metadata
is poll-only SSF Final, with no critical complex-subject members. All protocol
endpoints are on the pinned issuer's origin. No external SaaS account is
needed; Asterius's unchanged SSRF guard still requires a publicly reachable
HTTPS transmitter URL. Poll delivery does not require a publicly reachable
receiver callback. Subject mapping remains an explicit operator action.

The local control endpoint is `POST /emit-session-revoked`, authenticated with
the same private bearer, with JSON `{ "subject": "<owned-test-subject>" }`.
It emits an independently signed CAEP session-revoked SET with current
`event_timestamp` and issuer/subject identifier. Keep raw test subjects out of
shared evidence. The protocol endpoint never exposes this event trigger.

`python3 smoke.py --binary <owned-path>/ssfgo-transmitter` runs a disposable
loopback fixture, checks final metadata, bearer refusal, two streams, correlated
verification, independently verifies ES256 using Python cryptography, ACKs and
deletes exactly one stream. Its output explicitly records
`asterius_network_handoff=false` and `formal_conformance=false`. This passed
locally on 8 October 2026; it proves the candidate fixture, not Asterius
interoperability.

The real guarded Asterius network handoff passed on 8 October 2026 against
runtime source `790750f6fa69eecbf83fcfce8bce229020c3b77b`; see
[lifecycle evidence](../../docs/integrations/evidence/ssfgo-asterius-lifecycle-2026-10-08.json).
Fifteen checks include exact registered metadata/JWKS setup, readback, correlated
signed verification, explicit subject mapping, actual seeded-session revocation,
operator bearer reread refusal/recovery, lost ACK redelivery with one inbox row,
issuer refusal, exact stream deletion and continued delivery on a second stream.
The peer remains poll-only: push is correctly refused. The receiver's tenant
extractor wiring failure found by the handoff was corrected and checked through
its assembled-router PostgreSQL regression. This evidence targets SSF1 Final,
ALL subjects with explicit local mappings, operator bearer and ES256 poll;
it does not certify CAEP Draft01 or native push interoperability.

`lifecycle.py` operates only an explicitly owned `ast_product_*` database and
matches its private runtime/admin manifests. It uses DPoP admin HTTP for all
setup, mapping, verification, polling and deletion. SQL seeds a new isolated
peer/user/session and inspects effects, then removes only those fixture rows.
The source user/session is a controlled seed, not a browser login ceremony.
The negative issuer JWT mutation also has an invalid signature; the separate
unconfigured-issuer management control proves its route is not available.

The protocol relay's private one-shot ACK arm file is accessible only to the
operator, bound to the hash of the expected Authorization header. One matching
ACK is refused before native forwarding after Asterius's local commit, leaving
the exact SET available for a second poll. No public fault endpoint or key
export is introduced. The harness temporarily replaces only the explicitly
owned runtime-mounted SSF credential copy and restores it in `finally`;
it never mutates operator or native transmitter credentials. It retains a
private recovery manifest if remote stream outcome cannot be reconciled.
Invoke with explicit `--manifest`, `--automation`, `--database-container`,
`--peer-issuer`, `--bearer-file`, and the private `--ack-loss-directory` that
contains the approved relay configuration. Never run against an unowned database.
