# Educational PQ certificate format

The file is canonical JSON with this fixed field order:

```text
payload:
  version, subject, issuer, public_key_algorithm, public_key_pem_b64,
  created_utc, not_before_utc, not_after_utc
signature_algorithm
signature_b64
```

The ML-DSA signature covers the compact canonical serialization of `payload`.
The parser rejects missing, duplicate, reordered, extra, malformed-base64, or
unexpected fields. The embedded subject key must be an ML-DSA public key.

This format is an educational exercise and is not X.509.

