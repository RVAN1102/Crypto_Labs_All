#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pqtool {

using Bytes = std::vector<std::uint8_t>;

Bytes read_binary(const std::filesystem::path& path);
std::string read_text(const std::filesystem::path& path);
void write_binary_atomic(const std::filesystem::path& path, const Bytes& data);
void write_text_atomic(const std::filesystem::path& path, const std::string& data);

} // namespace pqtool

