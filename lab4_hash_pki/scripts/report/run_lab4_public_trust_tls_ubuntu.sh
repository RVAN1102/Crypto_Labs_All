#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-bavan.infinityfreeapp.com}"
ROOTCA="${2:-$HOME/https-lab/chain/Sectigo_Public_Server_Authentication_Root_E46.crt}"

LAB="lab4_hash_pki"
LOGS="$LAB/artifacts/ubuntu/logs"
TLSDIR="$LAB/artifacts/ubuntu/tls_public_trust"
REPORT="$LAB/report"

mkdir -p "$LOGS" "$TLSDIR" "$REPORT"

SCLIENT_LOG="$LOGS/public_trust_tls_ubuntu_s_client.log"
GATE_LOG="$LOGS/public_trust_tls_ubuntu_gate_brief.log"
CURL_LOG="$LOGS/public_trust_tls_ubuntu_curl.log"
APACHE_LOG="$LOGS/public_trust_tls_ubuntu_apache.log"
LEAF_INFO="$LOGS/public_trust_tls_ubuntu_leaf_cert.log"

CHAIN_PEM="$TLSDIR/public_trust_chain_ubuntu.pem"
LEAF_PEM="$TLSDIR/public_trust_leaf_ubuntu.pem"
ROOT_COPY="$TLSDIR/public_trust_root_ubuntu.pem"
SANITIZED="$TLSDIR/apache_public_trust_vhost_ubuntu_sanitized.conf"
CAPTURE="$REPORT/capture_commands_public_tls_ubuntu.md"

rm -f "$SCLIENT_LOG" "$GATE_LOG" "$CURL_LOG" "$APACHE_LOG" "$LEAF_INFO" \
      "$CHAIN_PEM" "$LEAF_PEM" "$ROOT_COPY" "$SANITIZED" "$CAPTURE"

if [ ! -f "$ROOTCA" ]; then
  echo "Root CA not found: $ROOTCA" >&2
  exit 1
fi

cp "$ROOTCA" "$ROOT_COPY"

sudo cp /etc/apache2/ssl/lab4-public-trust/lab4_bavan_fullchain.pem "$CHAIN_PEM"
sudo chown "$USER:$USER" "$CHAIN_PEM"

awk 'BEGIN{p=0} /-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{exit}' "$CHAIN_PEM" > "$LEAF_PEM"

{
  echo "Lab 4 Public Trust TLS Evidence - Ubuntu"
  echo "Domain: $DOMAIN"
  echo "RootCA: $ROOTCA"
  echo "Partial chain mode: enabled"
  echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
  openssl version

  echo
  echo "==== OpenSSL local Apache verification, SNI + hostname check ===="
  printf "Q\n" | openssl s_client \
    -connect 127.0.0.1:443 \
    -servername "$DOMAIN" \
    -verify_hostname "$DOMAIN" \
    -verify_return_error \
    -partial_chain \
    -CAfile "$ROOTCA" \
    -showcerts 2>&1 || true

  echo
  echo "==== OpenSSL brief verification ===="
  printf "Q\n" | openssl s_client \
    -connect 127.0.0.1:443 \
    -servername "$DOMAIN" \
    -verify_hostname "$DOMAIN" \
    -verify_return_error \
    -partial_chain \
    -CAfile "$ROOTCA" \
    -brief 2>&1 || true

  echo
  echo "==== Apache configured certificate chain PEM ===="
  cat "$CHAIN_PEM"
} | tee "$SCLIENT_LOG"

printf "Q\n" | openssl s_client \
  -connect 127.0.0.1:443 \
  -servername "$DOMAIN" \
  -verify_hostname "$DOMAIN" \
  -verify_return_error \
  -partial_chain \
  -CAfile "$ROOTCA" \
  -brief > "$GATE_LOG" 2>&1

openssl x509 -in "$LEAF_PEM" -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName | tee "$LEAF_INFO"

{
  echo "==== curl local Apache connection via --resolve ===="
  curl -Iv --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/" 2>&1 || true
} | tee "$CURL_LOG"

{
  echo "==== Apache syntax and vhost evidence ===="
  sudo apache2ctl configtest 2>&1
  sudo apache2ctl -S 2>&1
} | tee "$APACHE_LOG"

sudo sed -E 's#(SSLCertificateKeyFile[[:space:]]+).*#\1[REDACTED_PRIVATE_KEY_PATH]#' \
  /etc/apache2/sites-available/lab4-public-trust.conf > "$SANITIZED"
sudo chown "$USER:$USER" "$SANITIZED"

cat > "$CAPTURE" <<EOC
# Lab 4 Public Trust TLS capture commands - Ubuntu

openssl s_client -connect 127.0.0.1:443 -servername $DOMAIN -verify_hostname $DOMAIN -verify_return_error -partial_chain -CAfile "$ROOTCA" -showcerts

openssl s_client -connect 127.0.0.1:443 -servername $DOMAIN -verify_hostname $DOMAIN -verify_return_error -partial_chain -CAfile "$ROOTCA" -brief

curl -Iv --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/"

sudo apache2ctl configtest
sudo apache2ctl -S
EOC

grep -q "Verification: OK" "$GATE_LOG"
grep -q "Verified peername: $DOMAIN" "$GATE_LOG"

echo "PUBLIC TRUST TLS UBUNTU CHECK PASS"
echo "Logs:"
echo "$SCLIENT_LOG"
echo "$GATE_LOG"
echo "$CURL_LOG"
echo "$APACHE_LOG"
echo "$LEAF_INFO"
echo "Artifacts:"
echo "$CHAIN_PEM"
echo "$LEAF_PEM"
echo "$ROOT_COPY"
