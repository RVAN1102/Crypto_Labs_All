#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT/tests/certs"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

rm -f ./*.pem ./*.der ./*.csr ./*.srl
rm -rf ca_db
mkdir -p ca_db/newcerts
touch ca_db/index.txt
echo 1000 > ca_db/serial

cat > leaf_valid_ext.cnf <<'CNF'
[v3_leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:lab4-valid.test,DNS:localhost
CNF

cat > leaf_no_san_ext.cnf <<'CNF'
[v3_leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
CNF

cat > leaf_weak_ext.cnf <<'CNF'
[v3_leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:lab4-weak.test,DNS:localhost
CNF

cat > ca_sign.cnf <<'CNF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = ./ca_db
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
private_key = ./test_ca_key.pem
certificate = ./test_ca.pem
default_md = sha256
policy = policy_any
copy_extensions = copy
unique_subject = no

[ policy_any ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
CNF

echo "[1/8] Generating test CA"
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout test_ca_key.pem \
  -out test_ca.pem \
  -days 3650 \
  -sha256 \
  -subj "/CN=Lab4 Test CA" >/dev/null 2>&1

echo "[2/8] Generating wrong CA"
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout wrong_ca_key.pem \
  -out wrong_ca.pem \
  -days 3650 \
  -sha256 \
  -subj "/CN=Wrong Lab4 Test CA" >/dev/null 2>&1

echo "[3/8] Generating valid leaf certificate with SAN"
openssl req -newkey rsa:2048 -nodes \
  -keyout leaf_valid_key.pem \
  -out leaf_valid.csr \
  -subj "/CN=lab4-valid.test" >/dev/null 2>&1

openssl x509 -req \
  -in leaf_valid.csr \
  -CA test_ca.pem \
  -CAkey test_ca_key.pem \
  -CAcreateserial \
  -out leaf_valid.pem \
  -days 365 \
  -sha256 \
  -extfile leaf_valid_ext.cnf \
  -extensions v3_leaf >/dev/null 2>&1

openssl x509 -in leaf_valid.pem -outform DER -out leaf_valid.der

echo "[4/8] Generating leaf certificate without SAN"
openssl req -newkey rsa:2048 -nodes \
  -keyout leaf_no_san_key.pem \
  -out leaf_no_san.csr \
  -subj "/CN=lab4-no-san.test" >/dev/null 2>&1

openssl x509 -req \
  -in leaf_no_san.csr \
  -CA test_ca.pem \
  -CAkey test_ca_key.pem \
  -CAcreateserial \
  -out leaf_no_san.pem \
  -days 365 \
  -sha256 \
  -extfile leaf_no_san_ext.cnf \
  -extensions v3_leaf >/dev/null 2>&1

echo "[5/8] Generating weak RSA-1024 leaf certificate"
openssl req -newkey rsa:1024 -nodes \
  -keyout leaf_weak_key.pem \
  -out leaf_weak.csr \
  -subj "/CN=lab4-weak.test" >/dev/null 2>&1

openssl x509 -req \
  -in leaf_weak.csr \
  -CA test_ca.pem \
  -CAkey test_ca_key.pem \
  -CAcreateserial \
  -out leaf_weak.pem \
  -days 365 \
  -sha256 \
  -extfile leaf_weak_ext.cnf \
  -extensions v3_leaf >/dev/null 2>&1

echo "[6/8] Generating expired leaf certificate"
openssl req -newkey rsa:2048 -nodes \
  -keyout expired_leaf_key.pem \
  -out expired_leaf.csr \
  -subj "/CN=lab4-expired.test" >/dev/null 2>&1

openssl ca -batch \
  -config ca_sign.cnf \
  -in expired_leaf.csr \
  -out expired_leaf.pem \
  -startdate 20240101000000Z \
  -enddate 20240102000000Z \
  -extfile leaf_valid_ext.cnf \
  -extensions v3_leaf >/dev/null 2>&1

echo "[7/8] Creating malformed certificate"
printf '%s\n' "-----BEGIN CERTIFICATE-----" "not-a-valid-certificate" "-----END CERTIFICATE-----" > malformed_cert.pem

echo "[8/8] Done"
ls -1 leaf_valid.pem leaf_valid.der leaf_no_san.pem leaf_weak.pem expired_leaf.pem test_ca.pem wrong_ca.pem malformed_cert.pem
