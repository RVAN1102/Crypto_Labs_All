#include "aes_classic.hpp"

#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <cryptlib.h>

#include <iostream>
#include <stdexcept>
#include <string>

static constexpr size_t AES_BLOCK_SIZE_BYTES = 16;
static constexpr size_t ECB_DEFAULT_MAX_SIZE = 16 * 1024;

bool is_classic_aes_mode(const std::string& mode) {
    return mode == "ecb" ||
           mode == "cbc" ||
           mode == "cfb" ||
           mode == "ofb" ||
           mode == "ctr";
}

static void require_iv_16(const std::string& mode, const Bytes& iv) {
    if (iv.size() != AES_BLOCK_SIZE_BYTES) {
        throw std::runtime_error(
            "Invalid IV length for AES-" + mode + ". Expected 16 bytes."
        );
    }
}

static Bytes string_to_bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

Bytes aes_encrypt_classic(
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv,
    const Bytes& plaintext,
    bool allow_ecb,
    bool suppress_warning
) {
    std::string ciphertext;

    if (mode == "ecb") {
        if (!suppress_warning) {
            std::cerr << "WARNING: ECB mode is insecure because identical plaintext blocks produce identical ciphertext blocks.\n";
        }

        if (!allow_ecb && plaintext.size() > ECB_DEFAULT_MAX_SIZE) {
            throw std::runtime_error(
                "ECB is blocked for files larger than 16 KiB. Use --allow-ecb only for controlled lab testing."
            );
        }

        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKey(key.data(), key.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(ciphertext),
                CryptoPP::StreamTransformationFilter::PKCS_PADDING
            )
        );

        return string_to_bytes(ciphertext);
    }

    if (mode == "cbc") {
        require_iv_16(mode, iv);

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(ciphertext),
                CryptoPP::StreamTransformationFilter::PKCS_PADDING
            )
        );

        return string_to_bytes(ciphertext);
    }

    if (mode == "cfb") {
        require_iv_16(mode, iv);

        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

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

    if (mode == "ofb") {
        require_iv_16(mode, iv);

        CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

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

    if (mode == "ctr") {
        require_iv_16(mode, iv);

        CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

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

    throw std::runtime_error("Unsupported classic AES mode: " + mode);
}

Bytes aes_decrypt_classic(
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv,
    const Bytes& ciphertext,
    bool suppress_warning
) {
    std::string recovered;

    if (mode == "ecb") {
        if (!suppress_warning) {
            std::cerr << "WARNING: ECB mode is insecure and provides no semantic security.\n";
        }

        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKey(key.data(), key.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(recovered),
                CryptoPP::StreamTransformationFilter::PKCS_PADDING
            )
        );

        return string_to_bytes(recovered);
    }

    if (mode == "cbc") {
        require_iv_16(mode, iv);

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(recovered),
                CryptoPP::StreamTransformationFilter::PKCS_PADDING
            )
        );

        return string_to_bytes(recovered);
    }

    if (mode == "cfb") {
        require_iv_16(mode, iv);

        CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

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

    if (mode == "ofb") {
        require_iv_16(mode, iv);

        CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

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

    if (mode == "ctr") {
        require_iv_16(mode, iv);

        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

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

    throw std::runtime_error("Unsupported classic AES mode: " + mode);
}