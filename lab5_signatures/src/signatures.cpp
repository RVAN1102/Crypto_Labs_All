#include "sigtool/signatures.hpp"

#include "sigtool/encoding.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <memory>
#include <sstream>

namespace sigtool {

namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EcKeyPtr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BnCtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using EcPointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using EcdsaSigPtr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string openssl_error(const std::string& prefix) {
    std::ostringstream out;
    out << prefix;
    unsigned long code = ERR_get_error();
    if (code != 0) {
        char buf[256];
        ERR_error_string_n(code, buf, sizeof(buf));
        out << ": " << buf;
        while (ERR_get_error() != 0) {
        }
    }
    return out.str();
}

BioPtr mem_bio_from_bytes(const Bytes& data) {
    return BioPtr(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())), BIO_free);
}

bool bio_to_bytes(BIO* bio, Bytes& out, std::string& error) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (mem == nullptr) {
        error = "unable to read OpenSSL memory BIO";
        return false;
    }
    out.assign(reinterpret_cast<unsigned char*>(mem->data), reinterpret_cast<unsigned char*>(mem->data) + mem->length);
    return true;
}

bool write_private_key(EVP_PKEY* pkey, bool pem, Bytes& out, std::string& error) {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) {
        error = "unable to allocate BIO";
        return false;
    }
    const int ok = pem
        ? PEM_write_bio_PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr)
        : i2d_PrivateKey_bio(bio.get(), pkey);
    if (ok != 1) {
        error = openssl_error("unable to encode private key");
        return false;
    }
    return bio_to_bytes(bio.get(), out, error);
}

bool write_public_key(EVP_PKEY* pkey, bool pem, Bytes& out, std::string& error) {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) {
        error = "unable to allocate BIO";
        return false;
    }
    const int ok = pem ? PEM_write_bio_PUBKEY(bio.get(), pkey) : i2d_PUBKEY_bio(bio.get(), pkey);
    if (ok != 1) {
        error = openssl_error("unable to encode public key");
        return false;
    }
    return bio_to_bytes(bio.get(), out, error);
}

EvpPkeyPtr load_private_key(const Bytes& data, std::string& error) {
    BioPtr bio = mem_bio_from_bytes(data);
    if (!bio) {
        error = "unable to allocate key BIO";
        return EvpPkeyPtr(nullptr, EVP_PKEY_free);
    }
    EVP_PKEY* raw = looks_like_pem(data) ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)
                                         : d2i_PrivateKey_bio(bio.get(), nullptr);
    if (raw == nullptr) {
        error = openssl_error("malformed private key");
        return EvpPkeyPtr(nullptr, EVP_PKEY_free);
    }
    return EvpPkeyPtr(raw, EVP_PKEY_free);
}

EvpPkeyPtr load_public_key(const Bytes& data, std::string& error) {
    BioPtr bio = mem_bio_from_bytes(data);
    if (!bio) {
        error = "unable to allocate key BIO";
        return EvpPkeyPtr(nullptr, EVP_PKEY_free);
    }
    EVP_PKEY* raw = looks_like_pem(data) ? PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr)
                                         : d2i_PUBKEY_bio(bio.get(), nullptr);
    if (raw == nullptr) {
        error = openssl_error("malformed public key");
        return EvpPkeyPtr(nullptr, EVP_PKEY_free);
    }
    return EvpPkeyPtr(raw, EVP_PKEY_free);
}

bool validate_key(EVP_PKEY* pkey, Algorithm algorithm, bool private_key, std::string& error) {
    const int base = EVP_PKEY_base_id(pkey);
    if (algorithm == Algorithm::EcdsaP256) {
        if (base != EVP_PKEY_EC) {
            error = "key type is not EC for ecdsa-p256";
            return false;
        }
        EcKeyPtr ec(EVP_PKEY_get1_EC_KEY(pkey), EC_KEY_free);
        if (!ec) {
            error = openssl_error("unable to inspect EC key");
            return false;
        }
        const EC_GROUP* group = EC_KEY_get0_group(ec.get());
        if (group == nullptr || EC_GROUP_get_curve_name(group) != NID_X9_62_prime256v1) {
            error = "EC key is not NIST P-256 / secp256r1";
            return false;
        }
        if (private_key && EC_KEY_get0_private_key(ec.get()) == nullptr) {
            error = "EC private key is missing the private scalar";
            return false;
        }
        return true;
    }

    if (base != EVP_PKEY_RSA) {
        error = "key type is not RSA for rsa-pss-3072";
        return false;
    }
    if (EVP_PKEY_get_bits(pkey) != 3072) {
        error = "RSA key is not 3072 bits";
        return false;
    }
    (void)private_key;
    return true;
}

Bytes sha256(const Bytes& message) {
    Bytes digest(SHA256_DIGEST_LENGTH);
    SHA256(message.data(), message.size(), digest.data());
    return digest;
}

Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &out_len);
    out.resize(out_len);
    return out;
}

bool bn_to_fixed(const BIGNUM* value, std::size_t len, Bytes& out, std::string& error) {
    out.assign(len, 0);
    if (BN_bn2binpad(value, out.data(), static_cast<int>(len)) != static_cast<int>(len)) {
        error = "integer does not fit expected length";
        return false;
    }
    return true;
}

bool bits2octets(const Bytes& digest, const BIGNUM* q, std::size_t qlen_bytes, Bytes& out, std::string& error) {
    BnPtr z(BN_bin2bn(digest.data(), static_cast<int>(digest.size()), nullptr), BN_clear_free);
    if (!z) {
        error = "unable to convert digest to integer";
        return false;
    }
    if (BN_cmp(z.get(), q) >= 0 && BN_sub(z.get(), z.get(), q) != 1) {
        error = openssl_error("unable to reduce digest modulo order");
        return false;
    }
    return bn_to_fixed(z.get(), qlen_bytes, out, error);
}

bool rfc6979_generate_k(
    const BIGNUM* private_scalar,
    const BIGNUM* q,
    const Bytes& digest,
    BIGNUM* k_out,
    int retry,
    std::string& error) {

    constexpr std::size_t hlen = SHA256_DIGEST_LENGTH;
    const std::size_t qlen_bytes = 32;

    Bytes x;
    Bytes h1;
    if (!bn_to_fixed(private_scalar, qlen_bytes, x, error) || !bits2octets(digest, q, qlen_bytes, h1, error)) {
        return false;
    }

    Bytes v(hlen, 0x01);
    Bytes k(hlen, 0x00);

    Bytes bx;
    bx.reserve(v.size() + 1 + x.size() + h1.size());
    bx.insert(bx.end(), v.begin(), v.end());
    bx.push_back(0x00);
    bx.insert(bx.end(), x.begin(), x.end());
    bx.insert(bx.end(), h1.begin(), h1.end());
    k = hmac_sha256(k, bx);
    v = hmac_sha256(k, v);

    bx.clear();
    bx.insert(bx.end(), v.begin(), v.end());
    bx.push_back(0x01);
    bx.insert(bx.end(), x.begin(), x.end());
    bx.insert(bx.end(), h1.begin(), h1.end());
    k = hmac_sha256(k, bx);
    v = hmac_sha256(k, v);

    for (;;) {
        Bytes t;
        while (t.size() < qlen_bytes) {
            v = hmac_sha256(k, v);
            t.insert(t.end(), v.begin(), v.end());
        }
        BnPtr candidate(BN_bin2bn(t.data(), static_cast<int>(qlen_bytes), nullptr), BN_clear_free);
        if (!candidate) {
            error = "unable to convert RFC6979 candidate";
            return false;
        }
        if (BN_is_zero(candidate.get()) == 0 && BN_cmp(candidate.get(), q) < 0) {
            if (retry == 0) {
                if (BN_copy(k_out, candidate.get()) == nullptr) {
                    error = openssl_error("unable to copy RFC6979 nonce");
                    return false;
                }
                return true;
            }
            --retry;
        }

        Bytes retry_data;
        retry_data.reserve(v.size() + 1);
        retry_data.insert(retry_data.end(), v.begin(), v.end());
        retry_data.push_back(0x00);
        k = hmac_sha256(k, retry_data);
        v = hmac_sha256(k, v);
    }
}

bool deterministic_ecdsa_der(EC_KEY* ec, const Bytes& message, Bytes& der, std::string& error) {
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    const BIGNUM* private_scalar = EC_KEY_get0_private_key(ec);
    if (group == nullptr || private_scalar == nullptr) {
        error = "invalid EC private key";
        return false;
    }

    BnCtxPtr ctx(BN_CTX_new(), BN_CTX_free);
    BnPtr order(BN_new(), BN_clear_free);
    BnPtr half_order(BN_new(), BN_clear_free);
    BnPtr k(BN_new(), BN_clear_free);
    BnPtr x(BN_new(), BN_clear_free);
    BnPtr y(BN_new(), BN_clear_free);
    BnPtr r(BN_new(), BN_clear_free);
    BnPtr s(BN_new(), BN_clear_free);
    BnPtr e(BN_new(), BN_clear_free);
    BnPtr kinv(BN_new(), BN_clear_free);
    BnPtr tmp(BN_new(), BN_clear_free);
    EcPointPtr point(EC_POINT_new(group), EC_POINT_free);
    if (!ctx || !order || !half_order || !k || !x || !y || !r || !s || !e || !kinv || !tmp || !point) {
        error = "unable to allocate ECDSA temporaries";
        return false;
    }

    if (EC_GROUP_get_order(group, order.get(), ctx.get()) != 1 ||
        BN_rshift1(half_order.get(), order.get()) != 1) {
        error = openssl_error("unable to inspect EC group order");
        return false;
    }

    const Bytes digest = sha256(message);
    if (BN_bin2bn(digest.data(), static_cast<int>(digest.size()), e.get()) == nullptr ||
        (BN_cmp(e.get(), order.get()) >= 0 && BN_sub(e.get(), e.get(), order.get()) != 1)) {
        error = openssl_error("unable to derive ECDSA digest integer");
        return false;
    }

    for (int retry = 0; retry < 64; ++retry) {
        if (!rfc6979_generate_k(private_scalar, order.get(), digest, k.get(), retry, error)) {
            return false;
        }
        if (EC_POINT_mul(group, point.get(), k.get(), nullptr, nullptr, ctx.get()) != 1 ||
            EC_POINT_get_affine_coordinates(group, point.get(), x.get(), y.get(), ctx.get()) != 1 ||
            BN_nnmod(r.get(), x.get(), order.get(), ctx.get()) != 1) {
            error = openssl_error("unable to compute deterministic ECDSA point");
            return false;
        }
        if (BN_is_zero(r.get())) {
            continue;
        }
        if (BN_mod_mul(tmp.get(), r.get(), private_scalar, order.get(), ctx.get()) != 1 ||
            BN_mod_add(tmp.get(), tmp.get(), e.get(), order.get(), ctx.get()) != 1 ||
            BN_mod_inverse(kinv.get(), k.get(), order.get(), ctx.get()) == nullptr ||
            BN_mod_mul(s.get(), kinv.get(), tmp.get(), order.get(), ctx.get()) != 1) {
            error = openssl_error("unable to compute deterministic ECDSA scalar");
            return false;
        }
        if (BN_is_zero(s.get())) {
            continue;
        }
        if (BN_cmp(s.get(), half_order.get()) > 0 && BN_sub(s.get(), order.get(), s.get()) != 1) {
            error = openssl_error("unable to normalize ECDSA signature");
            return false;
        }

        EcdsaSigPtr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
        if (!sig) {
            error = "unable to allocate ECDSA signature";
            return false;
        }
        BIGNUM* r_owned = BN_dup(r.get());
        BIGNUM* s_owned = BN_dup(s.get());
        if (r_owned == nullptr || s_owned == nullptr || ECDSA_SIG_set0(sig.get(), r_owned, s_owned) != 1) {
            BN_clear_free(r_owned);
            BN_clear_free(s_owned);
            error = openssl_error("unable to assign ECDSA signature integers");
            return false;
        }
        const int len = i2d_ECDSA_SIG(sig.get(), nullptr);
        if (len <= 0) {
            error = openssl_error("unable to size ECDSA DER signature");
            return false;
        }
        der.assign(static_cast<std::size_t>(len), 0);
        unsigned char* p = der.data();
        if (i2d_ECDSA_SIG(sig.get(), &p) != len) {
            error = openssl_error("unable to encode ECDSA DER signature");
            return false;
        }
        return true;
    }

    error = "unable to produce non-zero deterministic ECDSA signature";
    return false;
}

bool ecdsa_der_to_raw(const Bytes& der, Bytes& raw, std::string& error) {
    const unsigned char* p = der.data();
    EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size())), ECDSA_SIG_free);
    if (!sig || p != der.data() + der.size()) {
        error = "malformed ECDSA DER signature";
        return false;
    }
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    Bytes rb;
    Bytes sb;
    if (!bn_to_fixed(r, 32, rb, error) || !bn_to_fixed(s, 32, sb, error)) {
        error = "ECDSA signature integer outside P-256 width";
        return false;
    }
    raw = rb;
    raw.insert(raw.end(), sb.begin(), sb.end());
    return true;
}

bool ecdsa_raw_to_der(const Bytes& raw, Bytes& der, std::string& error) {
    if (raw.size() != 64) {
        error = "raw ECDSA-P256 signatures must be 64 bytes";
        return false;
    }
    BIGNUM* r = BN_bin2bn(raw.data(), 32, nullptr);
    BIGNUM* s = BN_bin2bn(raw.data() + 32, 32, nullptr);
    EcdsaSigPtr sig(ECDSA_SIG_new(), ECDSA_SIG_free);
    if (r == nullptr || s == nullptr || !sig || ECDSA_SIG_set0(sig.get(), r, s) != 1) {
        BN_clear_free(r);
        BN_clear_free(s);
        error = openssl_error("unable to decode raw ECDSA signature");
        return false;
    }
    const int len = i2d_ECDSA_SIG(sig.get(), nullptr);
    if (len <= 0) {
        error = openssl_error("unable to size ECDSA DER signature");
        return false;
    }
    der.assign(static_cast<std::size_t>(len), 0);
    unsigned char* p = der.data();
    if (i2d_ECDSA_SIG(sig.get(), &p) != len) {
        error = openssl_error("unable to encode ECDSA DER signature");
        return false;
    }
    return true;
}

bool generate_ecdsa_p256(bool pem, KeyPair& out, std::string& error) {
    EcKeyPtr ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
    if (!ec) {
        error = openssl_error("unable to allocate ECDSA-P256 key");
        return false;
    }
    EC_KEY_set_asn1_flag(ec.get(), OPENSSL_EC_NAMED_CURVE);
    if (EC_KEY_generate_key(ec.get()) != 1) {
        error = openssl_error("unable to generate ECDSA-P256 key");
        return false;
    }
    EVP_PKEY* raw = EVP_PKEY_new();
    if (raw == nullptr || EVP_PKEY_assign_EC_KEY(raw, ec.release()) != 1) {
        EVP_PKEY_free(raw);
        error = openssl_error("unable to wrap EC key");
        return false;
    }
    EvpPkeyPtr pkey(raw, EVP_PKEY_free);
    return write_private_key(pkey.get(), pem, out.private_key, error) &&
           write_public_key(pkey.get(), pem, out.public_key, error);
}

bool generate_rsa_pss_3072(bool pem, KeyPair& out, std::string& error) {
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 3072) != 1) {
        error = openssl_error("unable to initialize RSA keygen");
        return false;
    }
    BnPtr exponent(BN_new(), BN_clear_free);
    if (!exponent || BN_set_word(exponent.get(), RSA_F4) != 1 ||
        EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx.get(), exponent.get()) != 1) {
        error = openssl_error("unable to configure RSA exponent");
        return false;
    }
    BIGNUM* exponent_released = exponent.release();
    (void)exponent_released;

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1 || raw == nullptr) {
        error = openssl_error("unable to generate RSA-3072 key");
        return false;
    }
    EvpPkeyPtr pkey(raw, EVP_PKEY_free);
    return write_private_key(pkey.get(), pem, out.private_key, error) &&
           write_public_key(pkey.get(), pem, out.public_key, error);
}

bool rsa_pss_sign(EVP_PKEY* pkey, const Bytes& message, Bytes& signature, std::string& error) {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        error = "unable to allocate signing context";
        return false;
    }
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, pkey) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) != 1 ||
        EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) != 1) {
        error = openssl_error("unable to initialize RSA-PSS signing");
        return false;
    }
    std::size_t len = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &len) != 1) {
        error = openssl_error("unable to size RSA-PSS signature");
        return false;
    }
    signature.assign(len, 0);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &len) != 1) {
        error = openssl_error("unable to create RSA-PSS signature");
        return false;
    }
    signature.resize(len);
    return true;
}

bool rsa_pss_verify(EVP_PKEY* pkey, const Bytes& message, const Bytes& signature, VerifyResult& result, std::string& error) {
    EvpMdCtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        error = "unable to allocate verify context";
        return false;
    }
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(ctx.get(), &pctx, EVP_sha256(), nullptr, pkey) != 1 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) != 1 ||
        EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) != 1) {
        error = openssl_error("unable to initialize RSA-PSS verification");
        return false;
    }
    const int ok = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
    if (ok == 1) {
        result.ok = true;
        result.detail = "signature verified";
        return true;
    }
    if (ok == 0) {
        result.ok = false;
        result.detail = "signature verification failed";
        while (ERR_get_error() != 0) {
        }
        return true;
    }
    error = openssl_error("RSA-PSS verification error");
    return false;
}

} // namespace

bool parse_algorithm(const std::string& text, Algorithm& algorithm) {
    const auto value = lower(text);
    if (value == "ecdsa-p256" || value == "p256" || value == "secp256r1") {
        algorithm = Algorithm::EcdsaP256;
        return true;
    }
    if (value == "rsa-pss-3072" || value == "rsapss-3072") {
        algorithm = Algorithm::RsaPss3072;
        return true;
    }
    return false;
}

std::string algorithm_name(Algorithm algorithm) {
    switch (algorithm) {
    case Algorithm::EcdsaP256: return "ecdsa-p256";
    case Algorithm::RsaPss3072: return "rsa-pss-3072";
    }
    return "unknown";
}

bool generate_key_pair(Algorithm algorithm, bool pem, KeyPair& out, std::string& error) {
    ERR_clear_error();
    if (algorithm == Algorithm::EcdsaP256) {
        return generate_ecdsa_p256(pem, out, error);
    }
    return generate_rsa_pss_3072(pem, out, error);
}

bool sign_message(
    Algorithm algorithm,
    const Bytes& private_key,
    const Bytes& message,
    SignatureEncoding encoding,
    Bytes& signature,
    std::string& error) {

    ERR_clear_error();
    EvpPkeyPtr pkey = load_private_key(private_key, error);
    if (!pkey || !validate_key(pkey.get(), algorithm, true, error)) {
        return false;
    }

    Bytes binary_signature;
    if (algorithm == Algorithm::EcdsaP256) {
        EcKeyPtr ec(EVP_PKEY_get1_EC_KEY(pkey.get()), EC_KEY_free);
        if (!ec || !deterministic_ecdsa_der(ec.get(), message, binary_signature, error)) {
            return false;
        }
        if (encoding == SignatureEncoding::Raw && !ecdsa_der_to_raw(binary_signature, binary_signature, error)) {
            return false;
        }
    } else {
        if (!rsa_pss_sign(pkey.get(), message, binary_signature, error)) {
            return false;
        }
    }

    if (encoding == SignatureEncoding::Base64) {
        const std::string rendered = base64_encode(binary_signature);
        signature.assign(rendered.begin(), rendered.end());
    } else {
        signature = binary_signature;
    }
    return true;
}

bool verify_message(
    Algorithm algorithm,
    const Bytes& public_key,
    const Bytes& message,
    const Bytes& signature,
    SignatureEncoding encoding,
    VerifyResult& result,
    std::string& error) {

    ERR_clear_error();
    result = VerifyResult{};
    EvpPkeyPtr pkey = load_public_key(public_key, error);
    if (!pkey || !validate_key(pkey.get(), algorithm, false, error)) {
        return false;
    }

    Bytes binary_signature = signature;
    if (encoding == SignatureEncoding::Base64) {
        const std::string text(signature.begin(), signature.end());
        if (!base64_decode(text, binary_signature, error)) {
            error = "malformed base64 signature: " + error;
            return false;
        }
        encoding = SignatureEncoding::Der;
    }

    if (algorithm == Algorithm::EcdsaP256) {
        Bytes der_signature;
        if (encoding == SignatureEncoding::Raw) {
            if (!ecdsa_raw_to_der(binary_signature, der_signature, error)) {
                return false;
            }
        } else {
            der_signature = binary_signature;
        }

        const unsigned char* p = der_signature.data();
        EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_signature.size())), ECDSA_SIG_free);
        if (!sig || p != der_signature.data() + der_signature.size()) {
            error = "malformed ECDSA DER signature";
            return false;
        }
        EcKeyPtr ec(EVP_PKEY_get1_EC_KEY(pkey.get()), EC_KEY_free);
        if (!ec) {
            error = openssl_error("unable to extract EC public key");
            return false;
        }
        const Bytes digest = sha256(message);
        const int ok = ECDSA_do_verify(digest.data(), static_cast<int>(digest.size()), sig.get(), ec.get());
        if (ok == 1) {
            result.ok = true;
            result.detail = "signature verified";
            return true;
        }
        if (ok == 0) {
            result.ok = false;
            result.detail = "signature verification failed";
            return true;
        }
        error = openssl_error("ECDSA verification error");
        return false;
    }

    return rsa_pss_verify(pkey.get(), message, binary_signature, result, error);
}

bool looks_like_pem(const Bytes& data) {
    const std::string text(data.begin(), data.end());
    return text.find("-----BEGIN ") != std::string::npos;
}

bool is_supported_hash_name(const std::string& hash_name) {
    return lower(hash_name) == "sha256";
}

} // namespace sigtool
