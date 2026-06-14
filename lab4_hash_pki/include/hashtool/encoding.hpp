#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hashtool {

using Bytes = std::vector<std::uint8_t>;

enum class Encoding {
    Hex,
    Base64,
    Raw
};

bool parse_encoding(const std::string& value, Encoding& encoding);
std::string hex_encode(const Bytes& bytes);
bool hex_decode(const std::string& text, Bytes& bytes, std::string& error);
std::string base64_encode(const Bytes& bytes);

} // namespace hashtool

