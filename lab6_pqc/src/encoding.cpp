#include "pqtool/encoding.hpp"

#include "pqtool/errors.hpp"
#include "pqtool/openssl_utils.hpp"

#include <openssl/evp.h>

#include <cctype>
#include <limits>

namespace pqtool {

std::string base64_encode(const Bytes& data) {
    if (data.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        fail("Input is too large for base64 encoding.");
    }
    std::string output(4 * ((data.size() + 2) / 3), '\0');
    if (!data.empty()) {
        const int written = EVP_EncodeBlock(
            reinterpret_cast<unsigned char*>(output.data()),
            data.data(),
            static_cast<int>(data.size()));
        openssl_require(written >= 0, "Base64 encoding");
        output.resize(static_cast<std::size_t>(written));
    }
    return output;
}

Bytes base64_decode(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    if ((text.size() % 4) != 0 ||
        text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        fail("Malformed base64 input.");
    }
    for (const unsigned char c : text) {
        if (!(std::isalnum(c) || c == '+' || c == '/' || c == '=')) {
            fail("Malformed base64 input.");
        }
    }
    const auto first_padding = text.find('=');
    if (first_padding != std::string::npos) {
        if (first_padding < text.size() - 2 ||
            text.find_first_not_of('=', first_padding) != std::string::npos) {
            fail("Malformed base64 padding.");
        }
    }
    Bytes output((text.size() / 4) * 3);
    const int decoded = EVP_DecodeBlock(
        output.data(),
        reinterpret_cast<const unsigned char*>(text.data()),
        static_cast<int>(text.size()));
    if (decoded < 0) {
        fail("Malformed base64 input.");
    }
    std::size_t padding = 0;
    if (!text.empty() && text.back() == '=') {
        ++padding;
    }
    if (text.size() > 1 && text[text.size() - 2] == '=') {
        ++padding;
    }
    output.resize(static_cast<std::size_t>(decoded) - padding);
    if (base64_encode(output) != text) {
        fail("Non-canonical base64 input.");
    }
    return output;
}

std::string hex_encode(const Bytes& data) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(data.size() * 2);
    for (const auto byte : data) {
        output.push_back(digits[byte >> 4]);
        output.push_back(digits[byte & 0x0f]);
    }
    return output;
}

Bytes hex_decode(const std::string& text) {
    if ((text.size() % 2) != 0) {
        fail("Malformed hex input.");
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    Bytes output;
    output.reserve(text.size() / 2);
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int high = nibble(text[i]);
        const int low = nibble(text[i + 1]);
        if (high < 0 || low < 0) {
            fail("Malformed hex input.");
        }
        output.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return output;
}

} // namespace pqtool
