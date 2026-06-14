#pragma once

#include "hashtool/encoding.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace hashtool {

struct LengthExtensionDemoResult {
    bool naive_original_verify = false;
    bool naive_forged_verify = false;
    bool hmac_forged_verify = false;
    std::string original_mac_hex;
    std::string forged_mac_hex;
    std::size_t guessed_key_length = 0;
    std::size_t glue_padding_size = 0;
};

Bytes sha256_glue_padding(std::uint64_t message_length_bytes);

bool sha256_length_extend(
    const Bytes& original_digest,
    std::uint64_t processed_length_before_extension,
    const Bytes& extension,
    Bytes& forged_digest,
    std::string& error);

bool run_length_extension_demo(
    const std::string& out_dir,
    LengthExtensionDemoResult& result,
    std::string& output,
    std::string& error);

} // namespace hashtool
