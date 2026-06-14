#include <gtest/gtest.h>

#include "aes_gcm.hpp"
#include "encoding.hpp"
#include "envelope.hpp"
#include "rsa_oaep.hpp"

#include <string>

static Bytes bytes_from_text(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

static Bytes make_plaintext(std::size_t n) {
    Bytes out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<unsigned char>(i & 0xffu);
    }
    return out;
}

TEST(RsaOaepUnitTest, RequiredPlaintextLimitsAreCorrect) {
    EXPECT_EQ(rsa_oaep_sha256_max_plaintext_for_bits(3072), 318u);
    EXPECT_EQ(rsa_oaep_sha256_max_plaintext_for_bits(4096), 446u);
}

TEST(RsaOaepUnitTest, RoundTripWithLabelWorks) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(3072);
    const Bytes label = bytes_from_text("lab3-label");
    const Bytes plaintext = bytes_from_text("small RSA-OAEP message");

    const Bytes ciphertext = rsa_oaep_sha256_encrypt_der(keys.public_key_der, plaintext, label);
    const Bytes recovered = rsa_oaep_sha256_decrypt_der(keys.private_key_der, ciphertext, label);

    EXPECT_EQ(ciphertext.size(), 384u);
    EXPECT_EQ(recovered, plaintext);
}

TEST(RsaOaepUnitTest, WrongLabelIsRejected) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(3072);
    const Bytes plaintext = bytes_from_text("label sensitive");
    const Bytes ciphertext = rsa_oaep_sha256_encrypt_der(keys.public_key_der, plaintext, bytes_from_text("right"));

    EXPECT_THROW(
        {
            (void)rsa_oaep_sha256_decrypt_der(keys.private_key_der, ciphertext, bytes_from_text("wrong"));
        },
        std::exception
    );
}

TEST(RsaOaepUnitTest, DirectPlaintextLimitIsEnforced) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(3072);
    const Bytes too_large = make_plaintext(319);

    EXPECT_THROW(
        {
            (void)rsa_oaep_sha256_encrypt_der(keys.public_key_der, too_large, Bytes{});
        },
        std::exception
    );
}

TEST(RsaOaepUnitTest, Rsa4096BoundaryLimitWorks) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(4096);
    const Bytes label = bytes_from_text("rsa4096-boundary");
    const Bytes max_plaintext = make_plaintext(446);
    const Bytes too_large = make_plaintext(447);

    const Bytes ciphertext = rsa_oaep_sha256_encrypt_der(keys.public_key_der, max_plaintext, label);
    const Bytes recovered = rsa_oaep_sha256_decrypt_der(keys.private_key_der, ciphertext, label);

    EXPECT_EQ(ciphertext.size(), 512u);
    EXPECT_EQ(recovered, max_plaintext);
    EXPECT_THROW(
        {
            (void)rsa_oaep_sha256_encrypt_der(keys.public_key_der, too_large, label);
        },
        std::exception
    );
}

TEST(AesGcmUnitTest, TamperedTagIsRejected) {
    const Bytes key(32, 0x11);
    const Bytes nonce(12, 0x22);
    const Bytes plaintext = make_plaintext(128);
    AesGcmCiphertext ct = aes_256_gcm_encrypt(key, nonce, plaintext);

    ct.tag[0] ^= 0x01;

    EXPECT_THROW(
        {
            (void)aes_256_gcm_decrypt(key, nonce, ct.ciphertext, ct.tag);
        },
        std::exception
    );
}

TEST(HybridEnvelopeUnitTest, HybridRoundTripWorks) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(3072);
    const Bytes label = bytes_from_text("hybrid-label");
    const Bytes plaintext = make_plaintext(4096);

    const HybridEncryptResult sealed = hybrid_encrypt(keys.public_key_der, plaintext, label, "cipher.bin");
    const Bytes recovered = hybrid_decrypt(keys.private_key_der, sealed.ciphertext, sealed.envelope, label);

    EXPECT_EQ(sealed.envelope.version, 1);
    EXPECT_EQ(sealed.envelope.rsa_bits, 3072);
    EXPECT_EQ(sealed.envelope.oaep_hash, "SHA-256");
    EXPECT_EQ(recovered, plaintext);
}

TEST(HybridEnvelopeUnitTest, TamperedCiphertextIsRejected) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(3072);
    const Bytes plaintext = make_plaintext(1024);
    HybridEncryptResult sealed = hybrid_encrypt(keys.public_key_der, plaintext, Bytes{}, "cipher.bin");

    sealed.ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        {
            (void)hybrid_decrypt(keys.private_key_der, sealed.ciphertext, sealed.envelope, Bytes{});
        },
        std::exception
    );
}

TEST(HybridEnvelopeUnitTest, TamperedEncryptedKeyIsRejected) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(3072);
    const Bytes plaintext = make_plaintext(1024);
    HybridEncryptResult sealed = hybrid_encrypt(keys.public_key_der, plaintext, Bytes{}, "cipher.bin");

    sealed.envelope.encrypted_key[0] ^= 0x01;

    EXPECT_THROW(
        {
            (void)hybrid_decrypt(keys.private_key_der, sealed.ciphertext, sealed.envelope, Bytes{});
        },
        std::exception
    );
}

TEST(HybridEnvelopeUnitTest, TamperedLabelIndicatorIsRejected) {
    const RsaKeyPairDer keys = generate_rsa_keypair_der(3072);
    const Bytes label = bytes_from_text("label-indicator");
    const Bytes plaintext = make_plaintext(1024);
    HybridEncryptResult sealed = hybrid_encrypt(keys.public_key_der, plaintext, label, "cipher.bin");

    sealed.envelope.oaep_label_present = false;

    EXPECT_THROW(
        {
            (void)hybrid_decrypt(keys.private_key_der, sealed.ciphertext, sealed.envelope, label);
        },
        std::exception
    );
}

TEST(HybridEnvelopeUnitTest, UnsupportedVersionIsRejected) {
    const std::string malformed =
        "{\n"
        "  \"version\": 99,\n"
        "  \"envelope_alg\": \"RSA-OAEP-SHA256+AES-256-GCM\",\n"
        "  \"key_alg\": \"RSA-OAEP-SHA256\",\n"
        "  \"content_alg\": \"AES-256-GCM\",\n"
        "  \"rsa_bits\": 3072,\n"
        "  \"oaep_hash\": \"SHA-256\",\n"
        "  \"oaep_label_present\": false,\n"
        "  \"oaep_label_sha256_hex\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\n"
        "  \"encrypted_key_hex\": \"00\",\n"
        "  \"nonce_hex\": \"000000000000000000000000\",\n"
        "  \"tag_hex\": \"00000000000000000000000000000000\",\n"
        "  \"ciphertext_mode\": \"external\",\n"
        "  \"ciphertext_file\": \"ct.bin\"\n"
        "}\n";

    EXPECT_THROW(
        {
            (void)HybridEnvelope::from_json(malformed);
        },
        std::exception
    );
}
