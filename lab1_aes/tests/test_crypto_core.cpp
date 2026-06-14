#include <gtest/gtest.h>

#include "aes_ccm.hpp"
#include "aes_classic.hpp"
#include "aes_gcm.hpp"
#include "aes_xts.hpp"
#include "encoding.hpp"

#include <stdexcept>
#include <string>
#include <vector>

static Bytes make_bytes(std::size_t n, unsigned char value) {
    return Bytes(n, value);
}

static Bytes make_plaintext(std::size_t n) {
    Bytes out(n);

    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<unsigned char>(i & 0xff);
    }

    return out;
}

TEST(AesGcmUnitTest, EncryptDecryptRoundTripWorks) {
    Bytes key = make_bytes(32, 0x11);
    Bytes nonce = make_bytes(12, 0x22);
    Bytes aad = {'l', 'a', 'b', '1', '-', 'a', 'a', 'd'};
    Bytes plaintext = make_plaintext(128);

    Bytes ciphertext;
    Bytes tag;

    aes_gcm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    ASSERT_EQ(ciphertext.size(), plaintext.size());
    ASSERT_EQ(tag.size(), 16u);

    Bytes recovered = aes_gcm_decrypt(key, nonce, aad, ciphertext, tag);

    EXPECT_EQ(recovered, plaintext);
}

TEST(AesGcmUnitTest, TamperedTagIsRejected) {
    Bytes key = make_bytes(32, 0x11);
    Bytes nonce = make_bytes(12, 0x22);
    Bytes aad = {'a', 'a', 'd'};
    Bytes plaintext = make_plaintext(64);

    Bytes ciphertext;
    Bytes tag;

    aes_gcm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    ASSERT_FALSE(tag.empty());
    tag[0] ^= 0x01;

    EXPECT_THROW(
        {
            (void)aes_gcm_decrypt(key, nonce, aad, ciphertext, tag);
        },
        std::exception
    );
}

TEST(AesGcmUnitTest, WrongAadIsRejected) {
    Bytes key = make_bytes(32, 0x11);
    Bytes nonce = make_bytes(12, 0x22);
    Bytes aad = {'c', 'o', 'r', 'r', 'e', 'c', 't'};
    Bytes wrong_aad = {'w', 'r', 'o', 'n', 'g'};
    Bytes plaintext = make_plaintext(64);

    Bytes ciphertext;
    Bytes tag;

    aes_gcm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    EXPECT_THROW(
        {
            (void)aes_gcm_decrypt(key, nonce, wrong_aad, ciphertext, tag);
        },
        std::exception
    );
}

TEST(AesCcmUnitTest, EncryptDecryptRoundTripWorks) {
    Bytes key = make_bytes(32, 0x33);
    Bytes nonce = make_bytes(12, 0x44);
    Bytes aad = {'c', 'c', 'm', '-', 'a', 'a', 'd'};
    Bytes plaintext = make_plaintext(128);

    Bytes ciphertext;
    Bytes tag;

    aes_ccm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    ASSERT_EQ(ciphertext.size(), plaintext.size());
    ASSERT_EQ(tag.size(), 16u);

    Bytes recovered = aes_ccm_decrypt(key, nonce, aad, ciphertext, tag);

    EXPECT_EQ(recovered, plaintext);
}

TEST(AesCcmUnitTest, TamperedCiphertextIsRejected) {
    Bytes key = make_bytes(32, 0x33);
    Bytes nonce = make_bytes(12, 0x44);
    Bytes aad = {'c', 'c', 'm'};
    Bytes plaintext = make_plaintext(64);

    Bytes ciphertext;
    Bytes tag;

    aes_ccm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    ASSERT_FALSE(ciphertext.empty());
    ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        {
            (void)aes_ccm_decrypt(key, nonce, aad, ciphertext, tag);
        },
        std::exception
    );
}

TEST(AesClassicUnitTest, CtrRoundTripWorks) {
    Bytes key = make_bytes(32, 0x55);
    Bytes iv = make_bytes(16, 0x66);
    Bytes plaintext = make_plaintext(1000);

    Bytes ciphertext = aes_encrypt_classic(
        "ctr",
        key,
        iv,
        plaintext,
        true,
        true
    );

    Bytes recovered = aes_decrypt_classic(
        "ctr",
        key,
        iv,
        ciphertext,
        true
    );

    EXPECT_EQ(recovered, plaintext);
}

TEST(AesClassicUnitTest, CbcRoundTripWorks) {
    Bytes key = make_bytes(32, 0x77);
    Bytes iv = make_bytes(16, 0x88);
    Bytes plaintext = make_plaintext(1000);

    Bytes ciphertext = aes_encrypt_classic(
        "cbc",
        key,
        iv,
        plaintext,
        true,
        true
    );

    Bytes recovered = aes_decrypt_classic(
        "cbc",
        key,
        iv,
        ciphertext,
        true
    );

    EXPECT_EQ(recovered, plaintext);
}

TEST(AesClassicUnitTest, InvalidCbcIvLengthIsRejected) {
    Bytes key = make_bytes(32, 0x77);
    Bytes bad_iv = make_bytes(8, 0x88);
    Bytes plaintext = make_plaintext(32);

    EXPECT_THROW(
        {
            (void)aes_encrypt_classic(
                "cbc",
                key,
                bad_iv,
                plaintext,
                true,
                true
            );
        },
        std::exception
    );
}

TEST(AesClassicUnitTest, EcbLargeFileIsBlockedWithoutAllowFlag) {
    Bytes key = make_bytes(32, 0x99);
    Bytes plaintext = make_plaintext(20 * 1024);

    EXPECT_THROW(
        {
            (void)aes_encrypt_classic(
                "ecb",
                key,
                Bytes{},
                plaintext,
                false,
                true
            );
        },
        std::exception
    );
}

TEST(AesXtsUnitTest, EncryptDecryptRoundTripWorks) {
    Bytes key = make_bytes(64, 0xaa);
    Bytes tweak = make_bytes(16, 0xbb);
    Bytes plaintext = make_plaintext(512);

    Bytes ciphertext = aes_xts_encrypt(key, tweak, plaintext);

    ASSERT_EQ(ciphertext.size(), plaintext.size());

    Bytes recovered = aes_xts_decrypt(key, tweak, ciphertext);

    EXPECT_EQ(recovered, plaintext);
}

TEST(AesXtsUnitTest, ShortDataUnitIsRejected) {
    Bytes key = make_bytes(64, 0xaa);
    Bytes tweak = make_bytes(16, 0xbb);
    Bytes short_plaintext = make_plaintext(8);

    EXPECT_THROW(
        {
            (void)aes_xts_encrypt(key, tweak, short_plaintext);
        },
        std::exception
    );
}