#!/bin/sh
# Generates the load client's signing key: a P-256 pair the k6 scripts sign
# with, and the JWK Set seed.sql registers so the server can verify them.
#
#     ./scripts/load/gen-keys.sh            # once, then reused
#     ./scripts/load/gen-keys.sh --force    # regenerate
#
# Output, in scripts/load/ (both ignored by git — a committed key would be a
# key every clone shares, load key or not):
#   client-key.der     PKCS#8 DER, what k6's WebCrypto imports
#   client.jwks.json   the public half as a JWK Set, `kid` load-key-1
#
# POSIX sh; needs openssl and a `base64` that takes standard input.
set -eu
DIR="${LOAD_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}"
KID="${KID:-load-key-1}"
force=0
[ "${1:-}" = "--force" ] && force=1

if [ "$force" -eq 0 ] && [ -s "$DIR/client-key.der" ] && [ -s "$DIR/client.jwks.json" ]; then
  printf 'load key already present in %s (--force to regenerate)\n' "$DIR"
  exit 0
fi

umask 077
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/client-key.pem"
openssl pkcs8 -topk8 -nocrypt -in "$DIR/client-key.pem" -outform DER -out "$DIR/client-key.der"

# The SubjectPublicKeyInfo of a P-256 key ends with the uncompressed point:
# 0x04, then X (32 bytes), then Y (32 bytes). RFC 7518 §6.2.1 wants each half
# base64url-encoded without padding.
b64url() { base64 | tr -d '\n=' | tr '+/' '-_'; }
openssl ec -in "$DIR/client-key.pem" -pubout -outform DER 2>/dev/null | tail -c 64 > "$DIR/.point"
x="$(head -c 32 "$DIR/.point" | b64url)"
y="$(tail -c 32 "$DIR/.point" | b64url)"
rm -f "$DIR/.point" "$DIR/client-key.pem"

printf '{"keys":[{"kty":"EC","crv":"P-256","kid":"%s","use":"sig","alg":"ES256","x":"%s","y":"%s"}]}\n' \
  "$KID" "$x" "$y" > "$DIR/client.jwks.json"
printf 'wrote %s and %s (kid %s)\n' "$DIR/client-key.der" "$DIR/client.jwks.json" "$KID"
