#include "aes_xts.hpp"

#include <aes.h>
#include <xts.h>
#include <filters.h>
#include <cryptlib.h>

#include <stdexcept>
#include <string>

static constexpr size_t XTS_TWEAK_SIZE = 16;
static constexpr size_t XTS_MIN_DATA_UNIT_SIZE = 16;

static void validate_xts_params(
    const Bytes& key,
    const Bytes& tweak,
    const Bytes& data
) {
    if (key.size() != 32 && key.size() != 64) {
        throw std::runtime_error("Invalid XTS key material length. Expected 32 or 64 bytes.");
    }

    if (tweak.size() != XTS_TWEAK_SIZE) {
        throw std::runtime_error("Invalid XTS tweak length. Expected 16 bytes.");
    }

    if (data.size() < XTS_MIN_DATA_UNIT_SIZE) {
        throw std::runtime_error("XTS input is too short. XTS requires at least 16 bytes.");
    }
}

static Bytes string_to_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

Bytes aes_xts_encrypt(
    const Bytes& key,
    const Bytes& tweak,
    const Bytes& plaintext
) {
    validate_xts_params(key, tweak, plaintext);

    CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), tweak.data());

    std::string ciphertext;

    CryptoPP::StringSource ss(
        plaintext.data(),
        plaintext.size(),
        true,
        new CryptoPP::StreamTransformationFilter(
            enc,
            new CryptoPP::StringSink(ciphertext),
            CryptoPP::StreamTransformationFilter::NO_PADDING
        )
    );

    return string_to_bytes(ciphertext);
}

Bytes aes_xts_decrypt(
    const Bytes& key,
    const Bytes& tweak,
    const Bytes& ciphertext
) {
    validate_xts_params(key, tweak, ciphertext);

    CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), tweak.data());

    std::string recovered;

    CryptoPP::StringSource ss(
        ciphertext.data(),
        ciphertext.size(),
        true,
        new CryptoPP::StreamTransformationFilter(
            dec,
            new CryptoPP::StringSink(recovered),
            CryptoPP::StreamTransformationFilter::NO_PADDING
        )
    );

    return string_to_bytes(recovered);
}