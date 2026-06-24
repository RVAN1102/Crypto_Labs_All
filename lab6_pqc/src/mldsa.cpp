#include "pqtool/mldsa.hpp"

#include "pqtool/errors.hpp"
#include "pqtool/openssl_utils.hpp"

#include <openssl/err.h>

namespace pqtool {

Bytes mldsa_sign(EVP_PKEY* private_key, const Bytes& message) {
    MdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    openssl_require(context != nullptr, "ML-DSA signing context");
    openssl_require(
        EVP_DigestSignInit_ex(context.get(), nullptr, nullptr, nullptr, nullptr, private_key, nullptr) == 1,
        "ML-DSA signing initialization");
    std::size_t signature_size = 0;
    openssl_require(
        EVP_DigestSign(context.get(), nullptr, &signature_size, message.data(), message.size()) == 1,
        "ML-DSA signature sizing");
    Bytes signature(signature_size);
    openssl_require(
        EVP_DigestSign(
            context.get(), signature.data(), &signature_size, message.data(), message.size()) == 1,
        "ML-DSA signing");
    signature.resize(signature_size);
    return signature;
}

bool mldsa_verify(EVP_PKEY* public_key, const Bytes& message, const Bytes& signature) {
    MdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    openssl_require(context != nullptr, "ML-DSA verification context");
    openssl_require(
        EVP_DigestVerifyInit_ex(context.get(), nullptr, nullptr, nullptr, nullptr, public_key, nullptr) == 1,
        "ML-DSA verification initialization");
    const int result = EVP_DigestVerify(
        context.get(), signature.data(), signature.size(), message.data(), message.size());
    if (result < 0) {
        ERR_clear_error();
        return false;
    }
    return result == 1;
}

} // namespace pqtool
