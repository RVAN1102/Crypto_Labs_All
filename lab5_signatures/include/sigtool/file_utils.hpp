#pragma once

#include "sigtool/types.hpp"

#include <string>

namespace sigtool {

bool read_binary_file(const std::string& path, Bytes& out, std::string& error);
bool write_binary_file(const std::string& path, const Bytes& data, std::string& error);
bool read_text_file(const std::string& path, std::string& out, std::string& error);
bool write_text_file(const std::string& path, const std::string& data, std::string& error);
bool path_exists(const std::string& path);
std::string json_escape(const std::string& text);

} // namespace sigtool
