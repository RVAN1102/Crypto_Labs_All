#include "encoding.hpp"

#include <hex.h>
#include <base64.h>
#include <filters.h>

#include <stdexcept>

std::string hex_encode(const Bytes& data) {
    std::string encoded;

    CryptoPP::StringSource ss(
        data.data(),
        data.size(),
        true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded),
            false
        )
    );

    return encoded;
}

Bytes hex_decode(const std::string& hex) {
    std::string decoded;

    try {
        CryptoPP::StringSource ss(
            hex,
            true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StringSink(decoded)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error(std::string("Invalid hex input: ") + e.what());
    }

    return Bytes(decoded.begin(), decoded.end());
}

std::string base64_encode(const Bytes& data) {
    std::string encoded;

    CryptoPP::StringSource ss(
        data.data(),
        data.size(),
        true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded),
            false
        )
    );

    return encoded;
}

std::string json_escape(const std::string& s) {
    std::string out;

    for (char c : s) {
        if (c == '\\') {
            out += "\\\\";
        } else if (c == '"') {
            out += "\\\"";
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\t') {
            out += "\\t";
        } else {
            out += c;
        }
    }

    return out;
}