#pragma once

#include "encoding.hpp"

void aes_gcm_encrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& plaintext,
    Bytes& ciphertext,
    Bytes& tag
);

Bytes aes_gcm_decrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& ciphertext,
    const Bytes& tag
);