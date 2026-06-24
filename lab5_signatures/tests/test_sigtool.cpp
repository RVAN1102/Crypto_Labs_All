#include "sigtool/encoding.hpp"
#include "sigtool/signatures.hpp"

#include <string>

#ifdef SIGTOOL_USE_GTEST
#include <gtest/gtest.h>
#else
#include <cstdlib>
#include <iostream>
#define EXPECT_TRUE(x) do { if (!(x)) { std::cerr << "EXPECT_TRUE failed: " #x "\n"; std::exit(1); } } while (0)
#define EXPECT_FALSE(x) do { if (x) { std::cerr << "EXPECT_FALSE failed: " #x "\n"; std::exit(1); } } while (0)
#define EXPECT_EQ(a, b) do { if (!((a) == (b))) { std::cerr << "EXPECT_EQ failed: " #a " == " #b "\n"; std::exit(1); } } while (0)
#define EXPECT_NE(a, b) do { if (!((a) != (b))) { std::cerr << "EXPECT_NE failed: " #a " != " #b "\n"; std::exit(1); } } while (0)
#define ASSERT_TRUE(x) EXPECT_TRUE(x)
#endif

namespace {

sigtool::Bytes bytes_from_text(const std::string& text) {
    return sigtool::Bytes(text.begin(), text.end());
}

void expect_verified(
    sigtool::Algorithm algorithm,
    const sigtool::Bytes& public_key,
    const sigtool::Bytes& message,
    const sigtool::Bytes& signature,
    sigtool::SignatureEncoding encoding) {

    std::string error;
    sigtool::VerifyResult result;
    EXPECT_TRUE(sigtool::verify_message(algorithm, public_key, message, signature, encoding, result, error));
    EXPECT_TRUE(result.ok);
}

void expect_not_verified(
    sigtool::Algorithm algorithm,
    const sigtool::Bytes& public_key,
    const sigtool::Bytes& message,
    const sigtool::Bytes& signature,
    sigtool::SignatureEncoding encoding) {

    std::string error;
    sigtool::VerifyResult result;
    const bool call_ok = sigtool::verify_message(algorithm, public_key, message, signature, encoding, result, error);
    EXPECT_TRUE(call_ok);
    EXPECT_FALSE(result.ok);
}

#ifdef SIGTOOL_USE_GTEST
TEST(SigtoolCore, EcdsaP256DeterministicAndNegativeCases)
#else
void test_ecdsa_p256_deterministic_and_negative_cases()
#endif
{
    std::string error;
    sigtool::KeyPair pair;
    ASSERT_TRUE(sigtool::generate_key_pair(sigtool::Algorithm::EcdsaP256, true, pair, error));

    const sigtool::Bytes message = {'l', 'a', 'b', '5', 0x00, 'm', 's', 'g'};
    sigtool::Bytes sig1;
    sigtool::Bytes sig2;
    ASSERT_TRUE(sigtool::sign_message(sigtool::Algorithm::EcdsaP256, pair.private_key, message, sigtool::SignatureEncoding::Der, sig1, error));
    ASSERT_TRUE(sigtool::sign_message(sigtool::Algorithm::EcdsaP256, pair.private_key, message, sigtool::SignatureEncoding::Der, sig2, error));
    EXPECT_EQ(sig1, sig2);
    expect_verified(sigtool::Algorithm::EcdsaP256, pair.public_key, message, sig1, sigtool::SignatureEncoding::Der);

    sigtool::Bytes raw_sig;
    ASSERT_TRUE(sigtool::sign_message(sigtool::Algorithm::EcdsaP256, pair.private_key, message, sigtool::SignatureEncoding::Raw, raw_sig, error));
    EXPECT_EQ(raw_sig.size(), 64U);
    expect_verified(sigtool::Algorithm::EcdsaP256, pair.public_key, message, raw_sig, sigtool::SignatureEncoding::Raw);

    sigtool::Bytes modified_message = message;
    modified_message[1] ^= 0x20;
    expect_not_verified(sigtool::Algorithm::EcdsaP256, pair.public_key, modified_message, sig1, sigtool::SignatureEncoding::Der);

    sigtool::Bytes modified_signature = sig1;
    modified_signature.back() ^= 0x01;
    expect_not_verified(sigtool::Algorithm::EcdsaP256, pair.public_key, message, modified_signature, sigtool::SignatureEncoding::Der);

    sigtool::KeyPair wrong_pair;
    ASSERT_TRUE(sigtool::generate_key_pair(sigtool::Algorithm::EcdsaP256, true, wrong_pair, error));
    expect_not_verified(sigtool::Algorithm::EcdsaP256, wrong_pair.public_key, message, sig1, sigtool::SignatureEncoding::Der);

    sigtool::VerifyResult result;
    EXPECT_FALSE(sigtool::verify_message(sigtool::Algorithm::RsaPss3072, pair.public_key, message, sig1, sigtool::SignatureEncoding::Der, result, error));

    sigtool::Bytes malformed_key = bytes_from_text("not a pem key");
    sigtool::Bytes ignored;
    EXPECT_FALSE(sigtool::sign_message(sigtool::Algorithm::EcdsaP256, malformed_key, message, sigtool::SignatureEncoding::Der, ignored, error));

    sigtool::Bytes malformed_signature = bytes_from_text("not der");
    EXPECT_FALSE(sigtool::verify_message(sigtool::Algorithm::EcdsaP256, pair.public_key, message, malformed_signature, sigtool::SignatureEncoding::Der, result, error));
}

#ifdef SIGTOOL_USE_GTEST
TEST(SigtoolCore, RsaPss3072RandomizedAndNegativeCases)
#else
void test_rsa_pss_3072_randomized_and_negative_cases()
#endif
{
    std::string error;
    sigtool::KeyPair pair;
    ASSERT_TRUE(sigtool::generate_key_pair(sigtool::Algorithm::RsaPss3072, true, pair, error));

    const sigtool::Bytes message = bytes_from_text("rsa-pss randomized salt test");
    sigtool::Bytes sig1;
    sigtool::Bytes sig2;
    ASSERT_TRUE(sigtool::sign_message(sigtool::Algorithm::RsaPss3072, pair.private_key, message, sigtool::SignatureEncoding::Raw, sig1, error));
    ASSERT_TRUE(sigtool::sign_message(sigtool::Algorithm::RsaPss3072, pair.private_key, message, sigtool::SignatureEncoding::Raw, sig2, error));
    EXPECT_NE(sig1, sig2);
    expect_verified(sigtool::Algorithm::RsaPss3072, pair.public_key, message, sig1, sigtool::SignatureEncoding::Raw);
    expect_verified(sigtool::Algorithm::RsaPss3072, pair.public_key, message, sig2, sigtool::SignatureEncoding::Raw);

    sigtool::Bytes b64_sig;
    ASSERT_TRUE(sigtool::sign_message(sigtool::Algorithm::RsaPss3072, pair.private_key, message, sigtool::SignatureEncoding::Base64, b64_sig, error));
    expect_verified(sigtool::Algorithm::RsaPss3072, pair.public_key, message, b64_sig, sigtool::SignatureEncoding::Base64);

    sigtool::Bytes modified_message = message;
    modified_message.push_back('!');
    expect_not_verified(sigtool::Algorithm::RsaPss3072, pair.public_key, modified_message, sig1, sigtool::SignatureEncoding::Raw);

    sigtool::Bytes modified_signature = sig1;
    modified_signature[7] ^= 0x40;
    expect_not_verified(sigtool::Algorithm::RsaPss3072, pair.public_key, message, modified_signature, sigtool::SignatureEncoding::Raw);

    sigtool::KeyPair wrong_pair;
    ASSERT_TRUE(sigtool::generate_key_pair(sigtool::Algorithm::RsaPss3072, true, wrong_pair, error));
    expect_not_verified(sigtool::Algorithm::RsaPss3072, wrong_pair.public_key, message, sig1, sigtool::SignatureEncoding::Raw);
}

#ifdef SIGTOOL_USE_GTEST
TEST(SigtoolCore, ParsingRejectsUnsupportedParameters)
#else
void test_parsing_rejects_unsupported_parameters()
#endif
{
    sigtool::Algorithm algorithm;
    sigtool::SignatureEncoding encoding;
    EXPECT_TRUE(sigtool::parse_algorithm("ecdsa-p256", algorithm));
    EXPECT_TRUE(sigtool::parse_algorithm("rsa-pss-3072", algorithm));
    EXPECT_FALSE(sigtool::parse_algorithm("ed25519", algorithm));
    EXPECT_TRUE(sigtool::parse_signature_encoding("der", encoding));
    EXPECT_TRUE(sigtool::parse_signature_encoding("raw", encoding));
    EXPECT_TRUE(sigtool::parse_signature_encoding("base64", encoding));
    EXPECT_FALSE(sigtool::parse_signature_encoding("hex", encoding));
    EXPECT_TRUE(sigtool::is_supported_hash_name("sha256"));
    EXPECT_FALSE(sigtool::is_supported_hash_name("sha512"));
}

} // namespace

#ifndef SIGTOOL_USE_GTEST
int main() {
    test_ecdsa_p256_deterministic_and_negative_cases();
    test_rsa_pss_3072_randomized_and_negative_cases();
    test_parsing_rejects_unsupported_parameters();
    return 0;
}
#endif
