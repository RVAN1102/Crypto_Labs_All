#pragma once

#include "encoding.hpp"

Bytes aes_xts_encrypt(
    const Bytes& key,
    const Bytes& tweak,
    const Bytes& plaintext
);

Bytes aes_xts_decrypt(
    const Bytes& key,
    const Bytes& tweak,
    const Bytes& ciphertext
);