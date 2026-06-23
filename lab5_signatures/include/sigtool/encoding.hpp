#pragma once

#include "sigtool/types.hpp"

#include <string>

namespace sigtool {

bool parse_signature_encoding(const std::string& text, SignatureEncoding& encoding);
std::string signature_encoding_name(SignatureEncoding encoding);

std::string hex_encode(const Bytes& data);
bool hex_decode(const std::string& text, Bytes& out, std::string& error);

std::string base64_encode(const Bytes& data);
bool base64_decode(const std::string& text, Bytes& out, std::string& error);

} // namespace sigtool
