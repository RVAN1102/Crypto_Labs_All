#pragma once

#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

std::string hex_encode(const Bytes& data);
Bytes hex_decode(const std::string& hex);
std::string base64_encode(const Bytes& data);
Bytes base64_decode(const std::string& base64);
std::string json_escape(const std::string& s);
std::string sha256_hex(const Bytes& data);
