#pragma once

#include "hashtool/encoding.hpp"

#include <string>

namespace hashtool {

bool read_binary_file(const std::string& path, Bytes& out, std::string& error);
bool write_binary_file(const std::string& path, const Bytes& data, std::string& error);
bool write_text_file(const std::string& path, const std::string& text, std::string& error);

} // namespace hashtool

