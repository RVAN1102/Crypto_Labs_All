#pragma once

#include "hashtool/encoding.hpp"

#include <cstddef>
#include <string>

namespace hashtool {

struct HashAlgorithm {
    std::string name;
    bool is_shake = false;
};

bool parse_hash_algorithm(const std::string& value, HashAlgorithm& algorithm);
bool is_supported_hash_algorithm(const std::string& value);
bool is_fixed_hash_algorithm(const std::string& value);

bool hash_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& input,
    std::size_t outlen,
    Bytes& digest,
    std::string& error);

bool hash_file_streaming(
    const HashAlgorithm& algorithm,
    const std::string& path,
    std::size_t outlen,
    Bytes& digest,
    std::string& error);

} // namespace hashtool

