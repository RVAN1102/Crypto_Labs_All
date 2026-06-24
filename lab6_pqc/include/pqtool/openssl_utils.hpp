#pragma once

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <memory>
#include <string>

namespace pqtool {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using SignaturePtr = std::unique_ptr<EVP_SIGNATURE, decltype(&EVP_SIGNATURE_free)>;

std::string openssl_error();
void openssl_require(bool condition, const std::string& operation);
std::string openssl_version_string();
void cleanse(void* data, std::size_t size);

} // namespace pqtool

