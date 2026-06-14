#pragma once

#include "encoding.hpp"

#include <cstddef>
#include <string>

struct RsaKeyPairDer {
    Bytes private_key_der;
    Bytes public_key_der;
    int bits;
};

RsaKeyPairDer generate_rsa_keypair_der(int bits);
void generate_rsa_keypair_der_files(
    int bits,
    const std::string& private_path,
    const std::string& public_path
);

std::string rsa_private_key_pem_from_der(const Bytes& private_key_der);
std::string rsa_public_key_pem_from_der(const Bytes& public_key_der);
Bytes rsa_key_der_from_pem_text(const std::string& pem_text);
Bytes load_rsa_private_key_file_der(const std::string& path);
Bytes load_rsa_public_key_file_der(const std::string& path);
void write_rsa_private_key_file_auto(const std::string& path, const Bytes& private_key_der);
void write_rsa_public_key_file_auto(const std::string& path, const Bytes& public_key_der);

int rsa_public_key_bits_der(const Bytes& public_key_der);
int rsa_private_key_bits_der(const Bytes& private_key_der);

std::size_t rsa_oaep_sha256_max_plaintext_for_bits(int rsa_bits);
std::size_t rsa_oaep_sha256_max_plaintext_der(const Bytes& public_key_der);

Bytes rsa_oaep_sha256_encrypt_der(
    const Bytes& public_key_der,
    const Bytes& plaintext,
    const Bytes& label
);

Bytes rsa_oaep_sha256_decrypt_der(
    const Bytes& private_key_der,
    const Bytes& ciphertext,
    const Bytes& label
);
