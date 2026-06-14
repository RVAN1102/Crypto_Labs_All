#include "aes_gcm.hpp"

#include <aes.h>
#include <filters.h>
#include <gcm.h>

#include <stdexcept>

static constexpr std::size_t AES_256_KEY_SIZE = 32;
static constexpr std::size_t GCM_NONCE_SIZE = 12;
static constexpr std::size_t GCM_TAG_SIZE = 16;

static void validate_aes_gcm_inputs(const Bytes& key, const Bytes& nonce) {
    if (key.size() != AES_256_KEY_SIZE) {
        throw std::runtime_error("Invalid AES-GCM key length. Expected 32 bytes for AES-256.");
    }

    if (nonce.size() != GCM_NONCE_SIZE) {
        throw std::runtime_error("Invalid AES-GCM nonce length. Expected 12 bytes.");
    }
}

AesGcmCiphertext aes_256_gcm_encrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& plaintext
) {
    validate_aes_gcm_inputs(key, nonce);

    std::string combined;
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    CryptoPP::StringSource ss(
        plaintext.data(),
        plaintext.size(),
        true,
        new CryptoPP::AuthenticatedEncryptionFilter(
            enc,
            new CryptoPP::StringSink(combined),
            false,
            static_cast<int>(GCM_TAG_SIZE)
        )
    );

    if (combined.size() < GCM_TAG_SIZE) {
        throw std::runtime_error("AES-GCM encryption produced malformed output.");
    }

    AesGcmCiphertext out;
    out.ciphertext.assign(combined.begin(), combined.end() - static_cast<std::ptrdiff_t>(GCM_TAG_SIZE));
    out.tag.assign(combined.end() - static_cast<std::ptrdiff_t>(GCM_TAG_SIZE), combined.end());
    return out;
}

Bytes aes_256_gcm_decrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& ciphertext,
    const Bytes& tag
) {
    validate_aes_gcm_inputs(key, nonce);

    if (tag.size() != GCM_TAG_SIZE) {
        throw std::runtime_error("Invalid AES-GCM tag length. Expected 16 bytes.");
    }

    std::string combined(ciphertext.begin(), ciphertext.end());
    combined.append(tag.begin(), tag.end());

    std::string recovered;
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    CryptoPP::StringSource ss(
        reinterpret_cast<const unsigned char*>(combined.data()),
        combined.size(),
        true,
        new CryptoPP::AuthenticatedDecryptionFilter(
            dec,
            new CryptoPP::StringSink(recovered),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            static_cast<int>(GCM_TAG_SIZE)
        )
    );

    return Bytes(recovered.begin(), recovered.end());
}
