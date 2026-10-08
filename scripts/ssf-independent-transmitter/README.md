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

For ticket evidence, still run the real guarded Asterius network path:
metadata/JWKS pinning, stream setup/readback, verification request and signed
poll processing, replay-safe ACK, explicit mapped-subject lifecycle action,
peer/audience refusal and exact-stream deletion while another stream remains.
Record the actual Asterius binary revision/hash, this upstream pin and sanitized
results. No ticket may close on the fixture smoke check alone.
