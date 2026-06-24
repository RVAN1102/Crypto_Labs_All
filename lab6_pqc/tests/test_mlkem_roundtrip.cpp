#include "pqtool/mlkem.hpp"
#include "pqtool/openssl_utils.hpp"
#include "pqtool/pq_key.hpp"

#include <gtest/gtest.h>

namespace {

void roundtrip(const char* algorithm) {
    auto key = pqtool::generate_key(algorithm);
    auto encapsulation = pqtool::mlkem_encapsulate(key.get());
    auto secret = pqtool::mlkem_decapsulate(key.get(), encapsulation.ciphertext);
    EXPECT_EQ(secret, encapsulation.shared_secret);
    pqtool::cleanse(secret.data(), secret.size());
    pqtool::cleanse(encapsulation.shared_secret.data(), encapsulation.shared_secret.size());
}

} // namespace

TEST(MlKem, Mlkem512Roundtrip) { roundtrip("ML-KEM-512"); }
TEST(MlKem, Mlkem768Roundtrip) { roundtrip("ML-KEM-768"); }

TEST(MlKem, ModifiedCiphertextMismatch) {
    auto key = pqtool::generate_key("ML-KEM-512");
    auto encapsulation = pqtool::mlkem_encapsulate(key.get());
    encapsulation.ciphertext[0] ^= 1;
    try {
        auto secret = pqtool::mlkem_decapsulate(key.get(), encapsulation.ciphertext);
        EXPECT_NE(secret, encapsulation.shared_secret);
        pqtool::cleanse(secret.data(), secret.size());
    } catch (const std::exception&) {
        SUCCEED();
    }
    pqtool::cleanse(encapsulation.shared_secret.data(), encapsulation.shared_secret.size());
}

TEST(MlKem, WrongPrivateKeyMismatch) {
    auto recipient = pqtool::generate_key("ML-KEM-512");
    auto wrong = pqtool::generate_key("ML-KEM-512");
    auto encapsulation = pqtool::mlkem_encapsulate(recipient.get());
    try {
        auto secret = pqtool::mlkem_decapsulate(wrong.get(), encapsulation.ciphertext);
        EXPECT_NE(secret, encapsulation.shared_secret);
        pqtool::cleanse(secret.data(), secret.size());
    } catch (const std::exception&) {
        SUCCEED();
    }
    pqtool::cleanse(encapsulation.shared_secret.data(), encapsulation.shared_secret.size());
}

