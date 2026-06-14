#include "hashtool/hash.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <memory>
#include <vector>

namespace hashtool {

namespace {

using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

const EVP_MD* evp_for_algorithm(const HashAlgorithm& algorithm) {
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
    if (algorithm.name == "shake128") {
        return EVP_shake128();
    }
    if (algorithm.name == "shake256") {
        return EVP_shake256();
    }
    return nullptr;
}

bool finish_digest(
    EVP_MD_CTX* ctx,
    const HashAlgorithm& algorithm,
    std::size_t outlen,
    Bytes& digest,
    std::string& error) {
    if (algorithm.is_shake) {
        if (outlen == 0) {
            error = "SHAKE requires --outlen";
            return false;
        }
        digest.assign(outlen, 0);
        if (EVP_DigestFinalXOF(ctx, digest.data(), digest.size()) != 1) {
            error = "OpenSSL SHAKE finalization failed";
            return false;
        }
        return true;
    }

    const int size = EVP_MD_CTX_size(ctx);
    if (size <= 0) {
        error = "OpenSSL fixed digest size unavailable";
        return false;
    }

    digest.assign(static_cast<std::size_t>(size), 0);
    unsigned int written = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &written) != 1) {
        error = "OpenSSL digest finalization failed";
        return false;
    }
    digest.resize(written);
    return true;
}

bool validate_output_length(const HashAlgorithm& algorithm, std::size_t outlen, std::string& error) {
    if (algorithm.is_shake) {
        if (outlen == 0) {
            error = "SHAKE requires --outlen";
            return false;
        }
        if (outlen > 1024 * 1024) {
            error = "SHAKE --outlen is too large";
            return false;
        }
        return true;
    }

    if (outlen != 0) {
        error = "fixed SHA-2/SHA-3 hashes reject --outlen";
        return false;
    }
    return true;
}

} // namespace

bool parse_hash_algorithm(const std::string& value, HashAlgorithm& algorithm) {
    const std::string lower = lowercase(value);
    algorithm = HashAlgorithm{lower, false};

    if (lower == "sha224" || lower == "sha256" || lower == "sha384" || lower == "sha512" ||
        lower == "sha3-224" || lower == "sha3-256" || lower == "sha3-384" || lower == "sha3-512") {
        return true;
    }

    if (lower == "shake128" || lower == "shake256") {
        algorithm.is_shake = true;
        return true;
    }

    return false;
}

bool is_supported_hash_algorithm(const std::string& value) {
    HashAlgorithm algorithm;
    return parse_hash_algorithm(value, algorithm);
}

bool is_fixed_hash_algorithm(const std::string& value) {
    HashAlgorithm algorithm;
    return parse_hash_algorithm(value, algorithm) && !algorithm.is_shake;
}

bool hash_bytes(
    const HashAlgorithm& algorithm,
    const Bytes& input,
    std::size_t outlen,
    Bytes& digest,
    std::string& error) {
    if (!validate_output_length(algorithm, outlen, error)) {
        return false;
    }

    const EVP_MD* md = evp_for_algorithm(algorithm);
    if (md == nullptr) {
        error = "unsupported hash algorithm";
        return false;
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        error = "failed to allocate OpenSSL digest context";
        return false;
    }

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        error = "OpenSSL digest initialization failed";
        return false;
    }

    if (!input.empty() && EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
        error = "OpenSSL digest update failed";
        return false;
    }

    return finish_digest(ctx.get(), algorithm, outlen, digest, error);
}

bool hash_file_streaming(
    const HashAlgorithm& algorithm,
    const std::string& path,
    std::size_t outlen,
    Bytes& digest,
    std::string& error) {
    if (!validate_output_length(algorithm, outlen, error)) {
        return false;
    }

    const EVP_MD* md = evp_for_algorithm(algorithm);
    if (md == nullptr) {
        error = "unsupported hash algorithm";
        return false;
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open input file: " + path;
        return false;
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        error = "failed to allocate OpenSSL digest context";
        return false;
    }

    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) {
        error = "OpenSSL digest initialization failed";
        return false;
    }

    std::array<char, 64 * 1024> buffer{};
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0 && EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<std::size_t>(got)) != 1) {
            error = "OpenSSL digest update failed";
            return false;
        }
    }

    if (!in.eof()) {
        error = "failed while reading input file: " + path;
        return false;
    }

    return finish_digest(ctx.get(), algorithm, outlen, digest, error);
}

} // namespace hashtool

