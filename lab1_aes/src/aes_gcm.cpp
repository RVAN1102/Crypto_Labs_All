#include "aes_gcm.hpp"

#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <cryptlib.h>

#include <stdexcept>
#include <string>

static constexpr int GCM_TAG_SIZE = 16;

void aes_gcm_encrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& plaintext,
    Bytes& ciphertext,
    Bytes& tag
) {
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    std::string cipher_and_tag;

    CryptoPP::AuthenticatedEncryptionFilter ef(
        enc,
        new CryptoPP::StringSink(cipher_and_tag),
        false,
        GCM_TAG_SIZE
    );

    if (!aad.empty()) {
        ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }

    ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!plaintext.empty()) {
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    }

    ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    if (cipher_and_tag.size() < static_cast<size_t>(GCM_TAG_SIZE)) {
        throw std::runtime_error("Internal error: GCM output shorter than tag size.");
    }

    const size_t cipher_len = cipher_and_tag.size() - GCM_TAG_SIZE;

    ciphertext.assign(
        cipher_and_tag.begin(),
        cipher_and_tag.begin() + static_cast<std::ptrdiff_t>(cipher_len)
    );

    tag.assign(
        cipher_and_tag.begin() + static_cast<std::ptrdiff_t>(cipher_len),
        cipher_and_tag.end()
    );
}

Bytes aes_gcm_decrypt(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& ciphertext,
    const Bytes& tag
) {
    if (tag.size() != static_cast<size_t>(GCM_TAG_SIZE)) {
        throw std::runtime_error("Invalid GCM tag length.");
    }

    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    std::string cipher_and_tag;
    cipher_and_tag.reserve(ciphertext.size() + tag.size());

    cipher_and_tag.append(
        reinterpret_cast<const char*>(ciphertext.data()),
        ciphertext.size()
    );

    cipher_and_tag.append(
        reinterpret_cast<const char*>(tag.data()),
        tag.size()
    );

    std::string recovered;

    CryptoPP::AuthenticatedDecryptionFilter df(
        dec,
        new CryptoPP::StringSink(recovered),
        CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION |
            CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END,
        GCM_TAG_SIZE
    );

    if (!aad.empty()) {
        df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }

    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!cipher_and_tag.empty()) {
        df.ChannelPut(
            CryptoPP::DEFAULT_CHANNEL,
            reinterpret_cast<const CryptoPP::byte*>(cipher_and_tag.data()),
            cipher_and_tag.size()
        );
    }

    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    return Bytes(recovered.begin(), recovered.end());
}