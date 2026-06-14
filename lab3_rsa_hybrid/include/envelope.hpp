#pragma once

#include "encoding.hpp"

#include <string>

struct HybridEnvelope {
    int version = 1;
    std::string envelope_alg = "RSA-OAEP-SHA256+AES-256-GCM";
    std::string key_alg = "RSA-OAEP-SHA256";
    std::string content_alg = "AES-256-GCM";
    int rsa_bits = 0;
    std::string oaep_hash = "SHA-256";
    bool oaep_label_present = false;
    std::string oaep_label_sha256_hex;
    Bytes encrypted_key;
    Bytes nonce;
    Bytes tag;
    std::string ciphertext_mode = "external";
    std::string ciphertext_file;

    std::string to_json() const;
    static HybridEnvelope from_json(const std::string& json);
};

struct HybridEncryptResult {
    Bytes ciphertext;
    HybridEnvelope envelope;
};

HybridEncryptResult hybrid_encrypt(
    const Bytes& public_key_der,
    const Bytes& plaintext,
    const Bytes& oaep_label,
    const std::string& ciphertext_file
);

Bytes hybrid_decrypt(
    const Bytes& private_key_der,
    const Bytes& ciphertext,
    const HybridEnvelope& envelope,
    const Bytes& oaep_label
);
