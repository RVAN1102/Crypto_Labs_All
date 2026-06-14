#pragma once

#include "encoding.hpp"

#include <string>

bool is_classic_aes_mode(const std::string& mode);

Bytes aes_encrypt_classic(
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv,
    const Bytes& plaintext,
    bool allow_ecb,
    bool suppress_warning = false
);

Bytes aes_decrypt_classic(
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv,
    const Bytes& ciphertext,
    bool suppress_warning = false
);