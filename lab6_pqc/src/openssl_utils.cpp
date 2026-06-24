#include "pqtool/openssl_utils.hpp"

#include "pqtool/errors.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

#include <array>

namespace pqtool {

std::string openssl_error() {
    const unsigned long code = ERR_peek_last_error();
    if (code == 0) {
        return "no OpenSSL detail";
    }
    std::array<char, 256> buffer{};
    ERR_error_string_n(code, buffer.data(), buffer.size());
    ERR_clear_error();
    return buffer.data();
}

void openssl_require(bool condition, const std::string& operation) {
    if (!condition) {
        fail(operation + " failed: " + openssl_error());
    }
}

std::string openssl_version_string() {
    return OpenSSL_version(OPENSSL_VERSION);
}

void cleanse(void* data, std::size_t size) {
    if (data != nullptr && size != 0) {
        OPENSSL_cleanse(data, size);
    }
}

} // namespace pqtool

