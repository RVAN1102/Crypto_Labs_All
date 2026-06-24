#include "pqtool/pq_key.hpp"

#include "pqtool/errors.hpp"
#include "pqtool/file_io.hpp"

#include <openssl/pem.h>

#include <algorithm>
#include <cctype>
#include <map>

namespace pqtool {
namespace {

BioPtr memory_bio() {
    BIO* bio = BIO_new(BIO_s_mem());
    openssl_require(bio != nullptr, "BIO allocation");
    return BioPtr(bio, BIO_free);
}

Bytes bio_bytes(BIO* bio) {
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio, &memory);
    openssl_require(memory != nullptr, "BIO extraction");
    return Bytes(
        reinterpret_cast<const std::uint8_t*>(memory->data),
        reinterpret_cast<const std::uint8_t*>(memory->data) + memory->length);
}

void require_key_type(EVP_PKEY* key, const std::string& algorithm) {
    if (key == nullptr || EVP_PKEY_is_a(key, algorithm.c_str()) != 1) {
        fail("Key algorithm does not match " + algorithm + ".");
    }
}

PkeyPtr read_private(const Bytes& bytes) {
    BioPtr bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())), BIO_free);
    openssl_require(bio != nullptr, "Private key input");
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if (key == nullptr) {
        fail("Malformed or unsupported private key.");
    }
    return PkeyPtr(key, EVP_PKEY_free);
}

PkeyPtr read_public(const Bytes& bytes) {
    BioPtr bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())), BIO_free);
    openssl_require(bio != nullptr, "Public key input");
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (key == nullptr) {
        fail("Malformed or unsupported public key.");
    }
    return PkeyPtr(key, EVP_PKEY_free);
}

} // namespace

std::string normalize_algorithm(const std::string& cli_name) {
    std::string lower = cli_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    static const std::map<std::string, std::string> algorithms{
        {"mldsa-44", "ML-DSA-44"},
        {"ml-dsa-44", "ML-DSA-44"},
        {"mldsa-65", "ML-DSA-65"},
        {"ml-dsa-65", "ML-DSA-65"},
        {"mlkem-512", "ML-KEM-512"},
        {"ml-kem-512", "ML-KEM-512"},
        {"mlkem-768", "ML-KEM-768"},
        {"ml-kem-768", "ML-KEM-768"},
    };
    const auto found = algorithms.find(lower);
    if (found == algorithms.end()) {
        fail("Unsupported algorithm: " + cli_name);
    }
    return found->second;
}

bool is_mldsa(const std::string& algorithm) {
    return algorithm == "ML-DSA-44" || algorithm == "ML-DSA-65";
}

bool is_mlkem(const std::string& algorithm) {
    return algorithm == "ML-KEM-512" || algorithm == "ML-KEM-768";
}

PkeyPtr generate_key(const std::string& algorithm) {
    if (!is_mldsa(algorithm) && !is_mlkem(algorithm)) {
        fail("Unsupported algorithm: " + algorithm);
    }
    PkeyCtxPtr context(EVP_PKEY_CTX_new_from_name(nullptr, algorithm.c_str(), nullptr), EVP_PKEY_CTX_free);
    openssl_require(context != nullptr, "Key generation context");
    openssl_require(EVP_PKEY_keygen_init(context.get()) == 1, "Key generation initialization");
    EVP_PKEY* raw = nullptr;
    openssl_require(EVP_PKEY_generate(context.get(), &raw) == 1, "Key generation");
    return PkeyPtr(raw, EVP_PKEY_free);
}

PkeyPtr load_private_key(const std::filesystem::path& path, const std::string& expected_algorithm) {
    PkeyPtr key = read_private(read_binary(path));
    require_key_type(key.get(), expected_algorithm);
    return key;
}

PkeyPtr load_public_key(const std::filesystem::path& path, const std::string& expected_algorithm) {
    PkeyPtr key = read_public(read_binary(path));
    require_key_type(key.get(), expected_algorithm);
    return key;
}

void save_private_key(const std::filesystem::path& path, EVP_PKEY* key) {
    BioPtr bio = memory_bio();
    openssl_require(
        PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
        "Private key serialization");
    write_binary_atomic(path, bio_bytes(bio.get()));
}

void save_public_key(const std::filesystem::path& path, EVP_PKEY* key) {
    BioPtr bio = memory_bio();
    openssl_require(PEM_write_bio_PUBKEY(bio.get(), key) == 1, "Public key serialization");
    write_binary_atomic(path, bio_bytes(bio.get()));
}

std::string public_key_pem(EVP_PKEY* key) {
    BioPtr bio = memory_bio();
    openssl_require(PEM_write_bio_PUBKEY(bio.get(), key) == 1, "Public key serialization");
    const Bytes bytes = bio_bytes(bio.get());
    return {bytes.begin(), bytes.end()};
}

PkeyPtr public_key_from_pem(const std::string& pem, const std::string& expected_algorithm) {
    const Bytes bytes(pem.begin(), pem.end());
    PkeyPtr key = read_public(bytes);
    require_key_type(key.get(), expected_algorithm);
    return key;
}

} // namespace pqtool

