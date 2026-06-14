#include "hashtool/encoding.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace hashtool {

namespace {

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

} // namespace

bool parse_encoding(const std::string& value, Encoding& encoding) {
    const std::string lower = lowercase(value);
    if (lower == "hex") {
        encoding = Encoding::Hex;
        return true;
    }
    if (lower == "base64") {
        encoding = Encoding::Base64;
        return true;
    }
    if (lower == "raw") {
        encoding = Encoding::Raw;
        return true;
    }
    return false;
}

std::string hex_encode(const Bytes& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        out << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return out.str();
}

bool hex_decode(const std::string& text, Bytes& bytes, std::string& error) {
    bytes.clear();
    if ((text.size() % 2) != 0) {
        error = "hex input must have an even number of characters";
        return false;
    }

    bytes.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int hi = hex_value(text[i]);
        const int lo = hex_value(text[i + 1]);
        if (hi < 0 || lo < 0) {
            error = "hex input contains a non-hex character";
            return false;
        }
        bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string base64_encode(const Bytes& bytes) {
    if (bytes.empty()) {
        return "";
    }
    std::string out;
    out.resize(4 * ((bytes.size() + 2) / 3));
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]),
        bytes.data(),
        static_cast<int>(bytes.size()));
    out.resize(static_cast<std::size_t>(written));
    return out;
}

} // namespace hashtool

