# Length-Extension Demo

This is an offline defensive lab demo only. It does not target any live service, network endpoint, or third-party system.

The intentionally insecure MAC is `SHA256(key || message)`. SHA-256 is a Merkle-Damgard hash: it processes fixed-size blocks and its final digest is the internal chaining state after padding has been processed. If an attacker knows the digest and can guess the length of the unknown prefix key, the attacker can reconstruct the exact glue padding that SHA-256 added after `key || message` and continue hashing extra bytes from that exposed state.

Glue padding is the SHA-256 padding bytes for the hidden `key || original_message`: a `0x80` byte, enough zero bytes to align the length field, and the original bit length encoded as a 64-bit big-endian integer. The forged visible message is `original_message || glue_padding || extension`; the secret key is not included in the file, but the verifier hashes `key || forged_message`, which recreates the same block stream.

Only the key length is needed because SHA-256 padding depends on message length, not key contents. The continuation helper starts from `original_mac` as the internal state and hashes the extension with the byte counter set to the length after glue padding.

HMAC prevents this attack because it does not expose the raw internal state of `SHA256(key || message)`. It hashes with separate inner and outer keyed domains, so continuing from an observed HMAC value does not produce a valid HMAC for an extended message.

Generated files:
- `demo_key.bin`: local test key only
- `original_message.txt`
- `original_mac.txt`
- `forged_message.bin`
- `forged_mac.txt`
- `padding_diagram.txt`
- `verification_result.txt`
