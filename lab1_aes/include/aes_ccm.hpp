#pragma once

#include "encoding.hpp"

void aes_ccm_encrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& plaintext,
    Bytes& ciphertext,
    Bytes& tag
);

Bytes aes_ccm_decrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& ciphertext,
    const Bytes& tag
);