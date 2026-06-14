#pragma once

#include "hashtool/encoding.hpp"
#include "hashtool/hash.hpp"

#include <string>

namespace hashtool {

bool hmac_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& key,
    const Bytes& input,
    Bytes& mac,
    std::string& error);

bool verify_hmac_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& key,
    const Bytes& input,
    const Bytes& expected_mac,
    bool& verified,
    std::string& error);

bool naive_mac_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& key,
    const Bytes& input,
    Bytes& mac,
    std::string& error);

} // namespace hashtool

