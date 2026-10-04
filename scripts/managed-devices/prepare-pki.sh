#!/usr/bin/env bash
# Generate only controlled disposable PKI; no existing operator trust is read.
set -euo pipefail
umask 077
: "${1:?Supply a new private fixture directory below /tmp/asterius-managed-device.}"
fixture_dir=$1
case "$fixture_dir" in /tmp/asterius-managed-device.*) ;; *) exit 2 ;; esac
mkdir -- "$fixture_dir"
ca() {
  local label=$1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -keyout "$fixture_dir/$label-ca-key.pem" -out "$fixture_dir/$label-ca.pem" \
    -subj "/CN=controlled-$label-CA" -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
}
leaf() {
  local label=$1 issuer=$2 usage=$3
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$fixture_dir/$label-key.pem" -out "$fixture_dir/$label.csr" \
    -subj "/CN=controlled-$label" 2>/dev/null
  cat > "$fixture_dir/$label.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$usage
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
  openssl x509 -req -in "$fixture_dir/$label.csr" -CA "$fixture_dir/$issuer-ca.pem" \
    -CAkey "$fixture_dir/$issuer-ca-key.pem" -CAcreateserial -days 1 \
    -extfile "$fixture_dir/$label.ext" -out "$fixture_dir/$label-cert.pem" 2>/dev/null
  rm -f -- "$fixture_dir/$label.csr" "$fixture_dir/$label.ext"
}
ca backend
ca proxy
ca device
ca unrelated
leaf backend backend serverAuth
leaf edge backend serverAuth
leaf proxy proxy clientAuth
leaf device device clientAuth
leaf unrelated-device unrelated clientAuth
leaf wrong-usage-device device serverAuth
leaf unpinned-proxy proxy clientAuth
# Public fixture fingerprints only; private keys and certificates are never logs.
openssl x509 -in "$fixture_dir/proxy-cert.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}' > "$fixture_dir/proxy-fingerprint.txt"
openssl x509 -in "$fixture_dir/device-cert.pem" -outform DER | openssl dgst -sha256 | awk '{print $NF}' > "$fixture_dir/device-fingerprint.txt"
