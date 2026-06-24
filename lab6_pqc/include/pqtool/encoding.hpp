#pragma once

#include "pqtool/file_io.hpp"

#include <string>

namespace pqtool {

std::string base64_encode(const Bytes& data);
Bytes base64_decode(const std::string& text);
std::string hex_encode(const Bytes& data);
Bytes hex_decode(const std::string& text);

} // namespace pqtool

