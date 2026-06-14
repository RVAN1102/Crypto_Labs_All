#include "hashtool/encoding.hpp"
#include "hashtool/hash.hpp"
#include "hashtool/mac.hpp"

#include <iostream>
#include <string>

#ifdef HASHTOOL_USE_GTEST
#include <gtest/gtest.h>
#endif

namespace {

using hashtool::Bytes;

bool sha256_abc_is_known() {
    hashtool::HashAlgorithm algorithm;
    if (!hashtool::parse_hash_algorithm("sha256", algorithm)) {
        return false;
    }
    const std::string text = "abc";
    const Bytes input(text.begin(), text.end());
    Bytes digest;
    std::string error;
    return hashtool::hash_bytes(algorithm, input, 0, digest, error) &&
        hashtool::hex_encode(digest) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
}

bool shake_requires_outlen() {
    hashtool::HashAlgorithm algorithm;
    if (!hashtool::parse_hash_algorithm("shake256", algorithm)) {
        return false;
    }
    Bytes digest;
    std::string error;
    return !hashtool::hash_bytes(algorithm, Bytes{}, 0, digest, error);
}

bool hmac_verify_rejects_wrong_mac() {
    hashtool::HashAlgorithm algorithm;
    if (!hashtool::parse_hash_algorithm("sha256", algorithm)) {
        return false;
    }
    const Bytes key{0x00, 0x11, 0x22};
    const std::string text = "hello";
    const Bytes input(text.begin(), text.end());
    const Bytes wrong_mac(32, 0x00);
    bool verified = true;
    std::string error;
    return hashtool::verify_hmac_bytes(algorithm, key, input, wrong_mac, verified, error) && !verified;
}

} // namespace

#ifdef HASHTOOL_USE_GTEST

TEST(HashCore, Sha256AbcMatchesKnownAnswer) {
    EXPECT_TRUE(sha256_abc_is_known());
}

TEST(HashCore, ShakeRequiresOutlen) {
    EXPECT_TRUE(shake_requires_outlen());
}

TEST(HashCore, HmacVerifyRejectsWrongMac) {
    EXPECT_TRUE(hmac_verify_rejects_wrong_mac());
}

#else

int run_one(const std::string& name, bool ok) {
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << "\n";
    return ok ? 0 : 1;
}

int main() {
    int fail = 0;
    fail += run_one("sha256 abc known answer", sha256_abc_is_known());
    fail += run_one("shake requires outlen", shake_requires_outlen());
    fail += run_one("wrong HMAC rejected", hmac_verify_rejects_wrong_mac());
    return fail == 0 ? 0 : 1;
}

#endif
