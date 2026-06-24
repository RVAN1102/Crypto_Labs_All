#include "pqtool/mldsa.hpp"
#include "pqtool/pq_key.hpp"

#include <gtest/gtest.h>

namespace {

const pqtool::Bytes message{'L', 'a', 'b', ' ', '6', 0x00, 0xff};

void roundtrip(const char* algorithm) {
    auto key = pqtool::generate_key(algorithm);
    const auto signature = pqtool::mldsa_sign(key.get(), message);
    EXPECT_TRUE(pqtool::mldsa_verify(key.get(), message, signature));
}

} // namespace

TEST(MlDsa, Mldsa44Roundtrip) { roundtrip("ML-DSA-44"); }
TEST(MlDsa, Mldsa65Roundtrip) { roundtrip("ML-DSA-65"); }

TEST(MlDsa, ModifiedMessageFails) {
    auto key = pqtool::generate_key("ML-DSA-44");
    const auto signature = pqtool::mldsa_sign(key.get(), message);
    auto modified = message;
    modified[0] ^= 1;
    EXPECT_FALSE(pqtool::mldsa_verify(key.get(), modified, signature));
}

TEST(MlDsa, ModifiedSignatureFails) {
    auto key = pqtool::generate_key("ML-DSA-44");
    auto signature = pqtool::mldsa_sign(key.get(), message);
    signature[0] ^= 1;
    EXPECT_FALSE(pqtool::mldsa_verify(key.get(), message, signature));
}

TEST(MlDsa, WrongPublicKeyFails) {
    auto signer = pqtool::generate_key("ML-DSA-44");
    auto wrong = pqtool::generate_key("ML-DSA-44");
    const auto signature = pqtool::mldsa_sign(signer.get(), message);
    EXPECT_FALSE(pqtool::mldsa_verify(wrong.get(), message, signature));
}

