#include "sigtool/encoding.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace sigtool {

namespace {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

std::string strip_ascii_ws(const std::string& text) {
    std::string out;
    for (unsigned char c : text) {
        if (!std::isspace(c)) {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

} // namespace

bool parse_signature_encoding(const std::string& text, SignatureEncoding& encoding) {
    const auto value = lower(text);
    if (value == "raw") {
        encoding = SignatureEncoding::Raw;
        return true;
    }
    if (value == "der") {
        encoding = SignatureEncoding::Der;
        return true;
    }
    if (value == "base64" || value == "b64") {
        encoding = SignatureEncoding::Base64;
        return true;
    }
    return false;
}

std::string signature_encoding_name(SignatureEncoding encoding) {
    switch (encoding) {
    case SignatureEncoding::Raw: return "raw";
    case SignatureEncoding::Der: return "der";
    case SignatureEncoding::Base64: return "base64";
    }
    return "unknown";
}

std::string hex_encode(const Bytes& data) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const unsigned char b : data) {
        out << std::setw(2) << static_cast<int>(b);
    }
    return out.str();
}

bool hex_decode(const std::string& text, Bytes& out, std::string& error) {
    const std::string compact = strip_ascii_ws(text);
    if ((compact.size() % 2) != 0) {
        error = "hex string has odd length";
        return false;
    }
    out.clear();
    out.reserve(compact.size() / 2);
    for (std::size_t i = 0; i < compact.size(); i += 2) {
        const int hi = hex_value(compact[i]);
        const int lo = hex_value(compact[i + 1]);
        if (hi < 0 || lo < 0) {
            error = "hex string contains non-hex character";
            return false;
        }
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

std::string base64_encode(const Bytes& data) {
    if (data.empty()) {
        return "";
    }
    std::string out(4 * ((data.size() + 2) / 3), '\0');
    const int len = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]),
        data.data(),
        static_cast<int>(data.size()));
    out.resize(static_cast<std::size_t>(len));
    return out;
}

bool base64_decode(const std::string& text, Bytes& out, std::string& error) {
    const std::string compact = strip_ascii_ws(text);
    if (compact.empty()) {
        out.clear();
        return true;
    }
    if ((compact.size() % 4) != 0) {
        error = "base64 length is not a multiple of 4";
        return false;
    }
    for (char c : compact) {
        const bool ok = std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=';
        if (!ok) {
            error = "base64 contains invalid character";
            return false;
        }
    }
    out.assign((compact.size() / 4) * 3, 0);
    const int decoded = EVP_DecodeBlock(
        out.data(),
        reinterpret_cast<const unsigned char*>(compact.data()),
        static_cast<int>(compact.size()));
    if (decoded < 0) {
        error = "malformed base64";
        return false;
    }
    std::size_t len = static_cast<std::size_t>(decoded);
    if (!compact.empty() && compact[compact.size() - 1] == '=') {
        --len;
        if (compact[compact.size() - 2] == '=') {
            --len;
        }
    }
    out.resize(len);
    return true;
}

} // namespace sigtool
