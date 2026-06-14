#include "rsa_oaep.hpp"

#include "file_utils.hpp"

#include <algparam.h>
#include <argnames.h>
#include <cryptlib.h>
#include <filters.h>
#include <osrng.h>
#include <rsa.h>
#include <sha.h>

#include <stdexcept>
#include <string>

static constexpr int RSA_MIN_BITS = 3072;
static constexpr int SHA256_BYTES = 32;

static void validate_supported_rsa_bits(int bits) {
    if (bits != 3072 && bits != 4096) {
        throw std::runtime_error("Unsupported RSA key size. Expected 3072 or 4096 bits.");
    }
}

static void validate_minimum_rsa_bits(int bits) {
    if (bits < RSA_MIN_BITS) {
        throw std::runtime_error("RSA modulus is too small. Minimum is 3072 bits.");
    }
}

static Bytes der_encode_private(const CryptoPP::RSA::PrivateKey& key) {
    std::string out;
    CryptoPP::StringSink sink(out);
    key.DEREncode(sink);
    return Bytes(out.begin(), out.end());
}

static Bytes der_encode_public(const CryptoPP::RSA::PublicKey& key) {
    std::string out;
    CryptoPP::StringSink sink(out);
    key.DEREncode(sink);
    return Bytes(out.begin(), out.end());
}

static CryptoPP::RSA::PrivateKey load_private_der(const Bytes& der) {
    CryptoPP::RSA::PrivateKey key;
    CryptoPP::ArraySource source(der.data(), der.size(), true);
    key.BERDecode(source);

    CryptoPP::AutoSeededRandomPool rng;
    if (!key.Validate(rng, 3)) {
        throw std::runtime_error("Invalid RSA private key.");
    }

    validate_minimum_rsa_bits(static_cast<int>(key.GetModulus().BitCount()));
    return key;
}

static CryptoPP::RSA::PublicKey load_public_der(const Bytes& der) {
    CryptoPP::RSA::PublicKey key;
    CryptoPP::ArraySource source(der.data(), der.size(), true);
    key.BERDecode(source);

    CryptoPP::AutoSeededRandomPool rng;
    if (!key.Validate(rng, 3)) {
        throw std::runtime_error("Invalid RSA public key.");
    }

    validate_minimum_rsa_bits(static_cast<int>(key.GetModulus().BitCount()));
    return key;
}

static CryptoPP::AlgorithmParameters label_parameters(const Bytes& label) {
    const unsigned char* ptr = label.empty() ? nullptr : label.data();
    return CryptoPP::MakeParameters(
        CryptoPP::Name::EncodingParameters(),
        CryptoPP::ConstByteArrayParameter(ptr, label.size())
    );
}

RsaKeyPairDer generate_rsa_keypair_der(int bits) {
    validate_supported_rsa_bits(bits);

    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey private_key;
    private_key.GenerateRandomWithKeySize(rng, static_cast<unsigned int>(bits));

    if (!private_key.Validate(rng, 3)) {
        throw std::runtime_error("Generated RSA private key failed validation.");
    }

    CryptoPP::RSA::PublicKey public_key(private_key);

    if (!public_key.Validate(rng, 3)) {
        throw std::runtime_error("Generated RSA public key failed validation.");
    }

    RsaKeyPairDer out;
    out.private_key_der = der_encode_private(private_key);
    out.public_key_der = der_encode_public(public_key);
    out.bits = bits;
    return out;
}

void generate_rsa_keypair_der_files(
    int bits,
    const std::string& private_path,
    const std::string& public_path
) {
    const RsaKeyPairDer pair = generate_rsa_keypair_der(bits);
    write_file_binary(private_path, pair.private_key_der);
    write_file_binary(public_path, pair.public_key_der);
}

int rsa_public_key_bits_der(const Bytes& public_key_der) {
    const CryptoPP::RSA::PublicKey key = load_public_der(public_key_der);
    return static_cast<int>(key.GetModulus().BitCount());
}

int rsa_private_key_bits_der(const Bytes& private_key_der) {
    const CryptoPP::RSA::PrivateKey key = load_private_der(private_key_der);
    return static_cast<int>(key.GetModulus().BitCount());
}

std::size_t rsa_oaep_sha256_max_plaintext_for_bits(int rsa_bits) {
    validate_minimum_rsa_bits(rsa_bits);
    const int bytes = rsa_bits / 8;
    const int max_len = bytes - (2 * SHA256_BYTES) - 2;

    if (max_len <= 0) {
        throw std::runtime_error("RSA modulus is too small for OAEP(SHA-256).");
    }

    return static_cast<std::size_t>(max_len);
}

std::size_t rsa_oaep_sha256_max_plaintext_der(const Bytes& public_key_der) {
    return rsa_oaep_sha256_max_plaintext_for_bits(rsa_public_key_bits_der(public_key_der));
}

Bytes rsa_oaep_sha256_encrypt_der(
    const Bytes& public_key_der,
    const Bytes& plaintext,
    const Bytes& label
) {
    const CryptoPP::RSA::PublicKey public_key = load_public_der(public_key_der);
    const int bits = static_cast<int>(public_key.GetModulus().BitCount());
    const std::size_t max_plaintext = rsa_oaep_sha256_max_plaintext_for_bits(bits);

    if (plaintext.size() > max_plaintext) {
        throw std::runtime_error(
            "Direct RSA-OAEP(SHA-256) plaintext too large. Use hybrid encryption for large files."
        );
    }

    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA256_Encryptor encryptor(public_key);
    Bytes ciphertext(encryptor.CiphertextLength(plaintext.size()));
    const CryptoPP::AlgorithmParameters params = label_parameters(label);

    encryptor.Encrypt(
        rng,
        plaintext.data(),
        plaintext.size(),
        ciphertext.data(),
        params
    );

    return ciphertext;
}

Bytes rsa_oaep_sha256_decrypt_der(
    const Bytes& private_key_der,
    const Bytes& ciphertext,
    const Bytes& label
) {
    const CryptoPP::RSA::PrivateKey private_key = load_private_der(private_key_der);
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA256_Decryptor decryptor(private_key);

    const std::size_t max_plaintext = decryptor.MaxPlaintextLength(ciphertext.size());
    if (max_plaintext == 0) {
        throw std::runtime_error("Invalid RSA-OAEP ciphertext length.");
    }

    Bytes recovered(max_plaintext);
    const CryptoPP::AlgorithmParameters params = label_parameters(label);
    const CryptoPP::DecodingResult result = decryptor.Decrypt(
        rng,
        ciphertext.data(),
        ciphertext.size(),
        recovered.data(),
        params
    );

    if (!result.isValidCoding) {
        throw std::runtime_error("RSA-OAEP(SHA-256) decryption failed.");
    }

    recovered.resize(result.messageLength);
    return recovered;
}
