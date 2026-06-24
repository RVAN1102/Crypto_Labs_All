#pragma once

#include "sigtool/types.hpp"

#include <string>

namespace sigtool {

bool parse_algorithm(const std::string& text, Algorithm& algorithm);
std::string algorithm_name(Algorithm algorithm);

bool generate_key_pair(Algorithm algorithm, bool pem, KeyPair& out, std::string& error);

bool sign_message(
    Algorithm algorithm,
    const Bytes& private_key,
    const Bytes& message,
    SignatureEncoding encoding,
    Bytes& signature,
    std::string& error);

bool verify_message(
    Algorithm algorithm,
    const Bytes& public_key,
    const Bytes& message,
    const Bytes& signature,
    SignatureEncoding encoding,
    VerifyResult& result,
    std::string& error);

bool looks_like_pem(const Bytes& data);
bool is_supported_hash_name(const std::string& hash_name);

} // namespace sigtool
