#pragma once

#include "pqtool/file_io.hpp"

#include <openssl/evp.h>

namespace pqtool {

struct Encapsulation {
    Bytes ciphertext;
    Bytes shared_secret;
};

Encapsulation mlkem_encapsulate(EVP_PKEY* public_key);
Bytes mlkem_decapsulate(EVP_PKEY* private_key, const Bytes& ciphertext);

} // namespace pqtool

