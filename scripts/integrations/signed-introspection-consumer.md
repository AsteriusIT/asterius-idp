This independent consumer exercises RFC 9701 against the explicitly owned
Asterius product fixture. It registers four dedicated UUID clients and one
nonce resource through guarded fixture SQL; actual token issuance and
introspection use HTTPS, private_key_jwt and a real DPoP-bound producer token.
It removes only its registered clients and resource in `finally`.

Run with the owned fixture manifest and database container:

```sh
python3 scripts/integrations/signed_introspection_consumer.py \
  --manifest /private/path/asterius-product-manifest.json \
  --database-container asterius-owned-fixture-pg
```

The Python `cryptography` Ed25519 verifier checks the returned signature,
protected algorithm/type/key, exact issuer and resource-client audience,
fresh issue time, nested introspection data and absence of top-level subject
or expiration. The consumer checks active token claims and inactive-only
privacy envelopes, and refuses altered signatures, wrong issuer/audience,
unexpected algorithm and JSON media downgrade. Real HTTP controls cover
unregistered response-algorithm refusal, wrong assertion algorithm and
unauthenticated signed/ordinary representation refusal.

The signed representation follows [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701.html),
including §5's HTTP 400 refusal for unauthenticated signed requests. Ordinary
RFC 7662 requests retain HTTP 401. No raw bearer tokens, assertions, keys or
subject identifiers appear in the sanitized evidence. This consumer is
independent of Asterius's JOSE implementation; its result is one piece of
Message Signing evidence, not a standalone FAPI certification.
