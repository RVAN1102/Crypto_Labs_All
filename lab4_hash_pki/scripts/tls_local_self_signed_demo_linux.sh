#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab4_root="$(cd "$script_dir/.." && pwd)"
out_dir="${1:-$lab4_root/demos/tls/local}"
tls_dir="$(dirname "$out_dir")"

mkdir -p "$out_dir"

if ! command -v openssl >/dev/null 2>&1; then
    echo "OpenSSL CLI not found on PATH. Install openssl and rerun this script." >&2
    exit 1
fi

key_path="$out_dir/localhost_ecdsa_key.pem"
cert_path="$out_dir/localhost_self_signed_cert.pem"
cnf_path="$out_dir/localhost_openssl.cnf"
cert_info="$tls_dir/cert_chain_info.txt"
test_log="$tls_dir/tls_test_log.txt"

cat > "$cnf_path" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = localhost

[v3_req]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$key_path"
openssl req -new -x509 -sha256 -key "$key_path" -out "$cert_path" -days 30 -config "$cnf_path"
openssl x509 -in "$cert_path" -noout -text > "$cert_info"

cat > "$test_log" <<EOF
TLS local self-signed practice run: PASS

Generated:
- $key_path
- $cert_path

This certificate is self-signed and valid only for local configuration practice.
It includes SAN DNS:localhost and IP:127.0.0.1.
No admin privileges were required.
No public trusted-root TLS deployment is claimed.
Trusted-root evidence remains pending until an owned domain and CA-issued certificate chain are available.
EOF

echo "Local self-signed TLS practice files created under: $out_dir"
echo "No public trust is claimed."

