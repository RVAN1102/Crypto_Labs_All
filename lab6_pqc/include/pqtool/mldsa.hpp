#pragma once

#include "pqtool/file_io.hpp"

#include <openssl/evp.h>

namespace pqtool {

Bytes mldsa_sign(EVP_PKEY* private_key, const Bytes& message);
bool mldsa_verify(EVP_PKEY* public_key, const Bytes& message, const Bytes& signature);

} // namespace pqtool

