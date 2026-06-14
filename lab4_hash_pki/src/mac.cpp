#include "hashtool/mac.hpp"

#include <openssl/crypto.h>
#include <openssl/hmac.h>

namespace hashtool {

namespace {

const EVP_MD* fixed_evp_for_algorithm(const HashAlgorithm& algorithm) {
    if (algorithm.is_shake) {
        return nullptr;
    }
    if (algorithm.name == "sha224") {
        return EVP_sha224();
    }
    if (algorithm.name == "sha256") {
        return EVP_sha256();
    }
    if (algorithm.name == "sha384") {
        return EVP_sha384();
    }
    if (algorithm.name == "sha512") {
        return EVP_sha512();
    }
    if (algorithm.name == "sha3-224") {
        return EVP_sha3_224();
    }
    if (algorithm.name == "sha3-256") {
        return EVP_sha3_256();
    }
    if (algorithm.name == "sha3-384") {
        return EVP_sha3_384();
    }
    if (algorithm.name == "sha3-512") {
        return EVP_sha3_512();
    }
    return nullptr;
}

} // namespace

bool hmac_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& key,
    const Bytes& input,
    Bytes& mac,
    std::string& error) {
    const EVP_MD* md = fixed_evp_for_algorithm(algorithm);
    if (md == nullptr) {
        error = "HMAC requires a supported fixed SHA-2/SHA-3 algorithm";
        return false;
    }

    mac.assign(static_cast<std::size_t>(EVP_MAX_MD_SIZE), 0);
    unsigned int written = 0;
    if (HMAC(
            md,
            key.data(),
            static_cast<int>(key.size()),
            input.data(),
            input.size(),
            mac.data(),
            &written) == nullptr) {
        error = "OpenSSL HMAC failed";
        return false;
    }
    mac.resize(written);
    return true;
}

bool verify_hmac_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& key,
    const Bytes& input,
    const Bytes& expected_mac,
    bool& verified,
    std::string& error) {
    Bytes actual;
    if (!hmac_bytes(algorithm, key, input, actual, error)) {
        return false;
    }

    verified = actual.size() == expected_mac.size() &&
        CRYPTO_memcmp(actual.data(), expected_mac.data(), actual.size()) == 0;
    return true;
}

bool naive_mac_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& key,
    const Bytes& input,
    Bytes& mac,
    std::string& error) {
    if (algorithm.is_shake) {
        error = "naive MAC requires a fixed SHA-2/SHA-3 algorithm";
        return false;
    }

    Bytes combined;
    combined.reserve(key.size() + input.size());
    combined.insert(combined.end(), key.begin(), key.end());
    combined.insert(combined.end(), input.begin(), input.end());
    return hash_bytes(algorithm, combined, 0, mac, error);
}

} // namespace hashtool

