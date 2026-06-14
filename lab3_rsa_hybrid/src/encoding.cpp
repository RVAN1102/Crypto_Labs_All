#include "encoding.hpp"

#include <filters.h>
#include <hex.h>
#include <sha.h>

#include <cctype>
#include <stdexcept>

std::string hex_encode(const Bytes& data) {
    std::string out;
    CryptoPP::StringSource ss(
        data.data(),
        data.size(),
        true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(out), false)
    );
    return out;
}

Bytes hex_decode(const std::string& hex) {
    if ((hex.size() % 2) != 0) {
        throw std::runtime_error("Invalid hex string length.");
    }

    for (char c : hex) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            throw std::runtime_error("Invalid hex string.");
        }
    }

    std::string decoded;
    CryptoPP::StringSource ss(
        hex,
        true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded))
    );

    return Bytes(decoded.begin(), decoded.end());
}

std::string json_escape(const std::string& s) {
    std::string out;

    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }

    return out;
}

std::string sha256_hex(const Bytes& data) {
    Bytes digest(CryptoPP::SHA256::DIGESTSIZE);
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(digest.data(), data.data(), data.size());
    return hex_encode(digest);
}
