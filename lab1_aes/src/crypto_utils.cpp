#include "crypto_utils.hpp"

#include "encoding.hpp"
#include "file_utils.hpp"

#include <osrng.h>

#include <stdexcept>

static constexpr int GCM_RECOMMENDED_NONCE_SIZE = 12;
static constexpr int AES_IV_SIZE = 16;
static constexpr int CCM_DEFAULT_NONCE_SIZE = 12;

Bytes random_bytes(size_t n) {
    Bytes out(n);

    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(out.data(), out.size());

    return out;
}

void validate_aes_key(const Bytes& key) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw std::runtime_error("Invalid AES key length. Expected 16, 24, or 32 bytes.");
    }
}

void validate_xts_key(const Bytes& key) {
    if (key.size() != 32 && key.size() != 64) {
        throw std::runtime_error("Invalid XTS key material length. Expected 32 or 64 bytes.");
    }
}

Bytes load_key(const std::map<std::string, std::string>& opts) {
    Bytes key;

    if (opts.count("key")) {
        key = read_file_binary(opts.at("key"));
    } else if (opts.count("key-hex")) {
        key = hex_decode(opts.at("key-hex"));
    } else {
        throw std::runtime_error("Missing key. Use --key FILE or --key-hex HEX.");
    }

    validate_aes_key(key);
    return key;
}

Bytes load_xts_key(const std::map<std::string, std::string>& opts) {
    Bytes key;

    if (opts.count("key")) {
        key = read_file_binary(opts.at("key"));
    } else if (opts.count("key-hex")) {
        key = hex_decode(opts.at("key-hex"));
    } else {
        throw std::runtime_error("Missing XTS key. Use --key FILE or --key-hex HEX.");
    }

    validate_xts_key(key);
    return key;
}

Bytes load_input_data(const std::map<std::string, std::string>& opts) {
    if (opts.count("text")) {
        const std::string text = opts.at("text");
        return Bytes(text.begin(), text.end());
    }

    if (opts.count("in")) {
        return read_file_binary(opts.at("in"));
    }

    throw std::runtime_error("Missing input. Use --in FILE or --text \"...\".");
}

Bytes load_aad(const std::map<std::string, std::string>& opts) {
    if (opts.count("aad-text")) {
        const std::string aad = opts.at("aad-text");
        return Bytes(aad.begin(), aad.end());
    }

    if (opts.count("aad")) {
        return read_file_binary(opts.at("aad"));
    }

    return {};
}

Bytes load_or_generate_gcm_nonce(const std::map<std::string, std::string>& opts) {
    Bytes nonce;

    if (opts.count("nonce")) {
        nonce = read_file_binary(opts.at("nonce"));
    } else if (opts.count("nonce-hex")) {
        nonce = hex_decode(opts.at("nonce-hex"));
    } else {
        nonce = random_bytes(GCM_RECOMMENDED_NONCE_SIZE);
    }

    if (nonce.size() != static_cast<size_t>(GCM_RECOMMENDED_NONCE_SIZE)) {
        throw std::runtime_error("Invalid GCM nonce length. Expected 12 bytes in current implementation.");
    }

    return nonce;
}

Bytes load_or_generate_ccm_nonce(const std::map<std::string, std::string>& opts) {
    Bytes nonce;

    if (opts.count("nonce")) {
        nonce = read_file_binary(opts.at("nonce"));
    } else if (opts.count("nonce-hex")) {
        nonce = hex_decode(opts.at("nonce-hex"));
    } else {
        nonce = random_bytes(CCM_DEFAULT_NONCE_SIZE);
    }

    if (nonce.size() < 7 || nonce.size() > 13) {
        throw std::runtime_error("Invalid CCM nonce length. Expected 7 to 13 bytes.");
    }

    return nonce;
}

Bytes load_or_generate_aes_iv(const std::map<std::string, std::string>& opts) {
    Bytes iv;

    if (opts.count("iv")) {
        iv = read_file_binary(opts.at("iv"));
    } else if (opts.count("iv-hex")) {
        iv = hex_decode(opts.at("iv-hex"));
    } else {
        iv = random_bytes(AES_IV_SIZE);
    }

    if (iv.size() != static_cast<size_t>(AES_IV_SIZE)) {
        throw std::runtime_error("Invalid AES IV length. Expected 16 bytes.");
    }

    return iv;
}