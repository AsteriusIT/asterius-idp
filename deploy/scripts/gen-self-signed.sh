#!/bin/sh
# Generates the self-signed certificate the example stack terminates TLS with.
#
#     ./deploy/scripts/gen-self-signed.sh            # once, then reused
#     ./deploy/scripts/gen-self-signed.sh --force    # regenerate
#     ASTERIUS_TLS_HOST=idp.lan ./deploy/scripts/gen-self-signed.sh --force
#
# The compose stack runs this same script in an init container (`certs`), so
# `docker compose up` needs no preparatory step; running it by hand is for
# changing the hostname or rotating the key.
#
# The output is a *development* certificate and it is never committed:
# deploy/certs/ is ignored by git. Replacing it with a real one is a matter of
# writing server.crt and server.key over these two files — see deploy/README.md.
#
# POSIX sh rather than bash: this also runs inside a minimal openssl image.
set -eu

CERT_DIR="${CERT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/../certs" && pwd)}"
HOST="${ASTERIUS_TLS_HOST:-localhost}"
DAYS="${ASTERIUS_TLS_DAYS:-825}"
force=0
[ "${1:-}" = "--force" ] && force=1

mkdir -p "$CERT_DIR"

if [ "$force" -eq 0 ] && [ -s "$CERT_DIR/server.crt" ] && [ -s "$CERT_DIR/server.key" ]; then
  printf 'certificate already present in %s (--force to regenerate)\n' "$CERT_DIR"
  exit 0
fi

# The SAN is what a client checks; the CN is decoration RFC 9525 §6.4 tells
# verifiers to ignore. A numeric host has to travel as iPAddress rather than
# DNS, or `curl https://127.0.0.1/` rejects the name.
case "$HOST" in
  localhost) san="DNS:localhost,IP:127.0.0.1" ;;
  *[!0-9.]*) san="DNS:$HOST" ;;
  *) san="IP:$HOST" ;;
esac

# CA:TRUE on a self-signed leaf so that it can be its own trust anchor:
# `curl --cacert server.crt https://localhost/` then verifies, instead of
# needing --insecure. OpenSSL will not accept a non-CA certificate as an
# anchor, and a demo whose only verification gesture is "turn verification
# off" teaches the wrong reflex.
#
# Written under temporary names and renamed into place. The compose stack
# generates this pair from an init container running as root, so the files it
# leaves behind are root-owned; a rename needs write permission on the
# *directory* rather than on the file, which is what lets an ordinary user
# re-run this with --force afterwards.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -noenc \
  -days "$DAYS" \
  -subj "/CN=$HOST" \
  -addext "subjectAltName=$san" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$CERT_DIR/.server.key.new" \
  -out "$CERT_DIR/.server.crt.new" >/dev/null

# nginx reads the key as a different uid than whoever generated it. This is a
# development key in a git-ignored directory, but world-readable private keys
# are still a habit worth not forming.
chmod 644 "$CERT_DIR/.server.crt.new"
chmod 640 "$CERT_DIR/.server.key.new"

mv -f "$CERT_DIR/.server.crt.new" "$CERT_DIR/server.crt"
mv -f "$CERT_DIR/.server.key.new" "$CERT_DIR/server.key"

printf 'wrote %s/server.crt and %s/server.key (SAN %s, %s days)\n' \
  "$CERT_DIR" "$CERT_DIR" "$san" "$DAYS"
