#include "pqtool/mlkem.hpp"

#include "pqtool/errors.hpp"
#include "pqtool/openssl_utils.hpp"

#include <openssl/err.h>

namespace pqtool {

Encapsulation mlkem_encapsulate(EVP_PKEY* public_key) {
    PkeyCtxPtr context(EVP_PKEY_CTX_new_from_pkey(nullptr, public_key, nullptr), EVP_PKEY_CTX_free);
    openssl_require(context != nullptr, "ML-KEM encapsulation context");
    openssl_require(EVP_PKEY_encapsulate_init(context.get(), nullptr) == 1, "ML-KEM encapsulation initialization");
    std::size_t ciphertext_size = 0;
    std::size_t secret_size = 0;
    openssl_require(
        EVP_PKEY_encapsulate(context.get(), nullptr, &ciphertext_size, nullptr, &secret_size) == 1,
        "ML-KEM output sizing");
    Encapsulation result{Bytes(ciphertext_size), Bytes(secret_size)};
    openssl_require(
        EVP_PKEY_encapsulate(
            context.get(),
            result.ciphertext.data(),
            &ciphertext_size,
            result.shared_secret.data(),
            &secret_size) == 1,
        "ML-KEM encapsulation");
    result.ciphertext.resize(ciphertext_size);
    result.shared_secret.resize(secret_size);
    return result;
}

Bytes mlkem_decapsulate(EVP_PKEY* private_key, const Bytes& ciphertext) {
    PkeyCtxPtr context(EVP_PKEY_CTX_new_from_pkey(nullptr, private_key, nullptr), EVP_PKEY_CTX_free);
    openssl_require(context != nullptr, "ML-KEM decapsulation context");
    openssl_require(EVP_PKEY_decapsulate_init(context.get(), nullptr) == 1, "ML-KEM decapsulation initialization");
    std::size_t secret_size = 0;
    if (EVP_PKEY_decapsulate(
            context.get(), nullptr, &secret_size, ciphertext.data(), ciphertext.size()) != 1) {
        ERR_clear_error();
        fail("ML-KEM decapsulation failed.");
    }
    Bytes secret(secret_size);
    if (EVP_PKEY_decapsulate(
            context.get(), secret.data(), &secret_size, ciphertext.data(), ciphertext.size()) != 1) {
        cleanse(secret.data(), secret.size());
        ERR_clear_error();
        fail("ML-KEM decapsulation failed.");
    }
    secret.resize(secret_size);
    return secret;
}

} // namespace pqtool
