#pragma once

#include "encoding.hpp"

struct AesGcmCiphertext {
    Bytes ciphertext;
    Bytes tag;
};

AesGcmCiphertext aes_256_gcm_encrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& plaintext
);

Bytes aes_256_gcm_decrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& ciphertext,
    const Bytes& tag
);
