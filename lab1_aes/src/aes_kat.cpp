#include "aes_kat.hpp"

#include "cli.hpp"
#include "encoding.hpp"
#include "file_utils.hpp"

#include <aes.h>
#include <ccm.h>
#include <gcm.h>
#include <modes.h>
#include <filters.h>
#include <cryptlib.h>

#include <cctype>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

using JsonObject = std::map<std::string, std::string>;

static void skip_ws(const std::string& s, size_t& pos) {
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) {
        ++pos;
    }
}

static void expect_char(const std::string& s, size_t& pos, char expected) {
    skip_ws(s, pos);

    if (pos >= s.size() || s[pos] != expected) {
        throw std::runtime_error(std::string("Malformed JSON. Expected '") + expected + "'.");
    }

    ++pos;
}

static std::string parse_json_string_value(const std::string& s, size_t& pos) {
    skip_ws(s, pos);

    if (pos >= s.size() || s[pos] != '"') {
        throw std::runtime_error("Malformed JSON. Expected string.");
    }

    ++pos;

    std::string out;

    while (pos < s.size()) {
        char c = s[pos++];

        if (c == '"') {
            return out;
        }

        if (c == '\\') {
            if (pos >= s.size()) {
                throw std::runtime_error("Malformed JSON escape.");
            }

            char e = s[pos++];

            if (e == '"' || e == '\\' || e == '/') {
                out += e;
            } else if (e == 'n') {
                out += '\n';
            } else if (e == 'r') {
                out += '\r';
            } else if (e == 't') {
                out += '\t';
            } else {
                throw std::runtime_error("Unsupported JSON escape sequence.");
            }
        } else {
            out += c;
        }
    }

    throw std::runtime_error("Unterminated JSON string.");
}

static JsonObject parse_json_object(const std::string& s, size_t& pos) {
    JsonObject obj;

    expect_char(s, pos, '{');

    skip_ws(s, pos);

    if (pos < s.size() && s[pos] == '}') {
        ++pos;
        return obj;
    }

    while (pos < s.size()) {
        std::string key = parse_json_string_value(s, pos);

        expect_char(s, pos, ':');

        std::string value = parse_json_string_value(s, pos);

        obj[key] = value;

        skip_ws(s, pos);

        if (pos < s.size() && s[pos] == ',') {
            ++pos;
            continue;
        }

        if (pos < s.size() && s[pos] == '}') {
            ++pos;
            return obj;
        }

        throw std::runtime_error("Malformed JSON object.");
    }

    throw std::runtime_error("Unterminated JSON object.");
}

static std::vector<JsonObject> parse_json_array_of_objects(const std::string& s) {
    std::vector<JsonObject> objects;
    size_t pos = 0;

    expect_char(s, pos, '[');

    skip_ws(s, pos);

    if (pos < s.size() && s[pos] == ']') {
        return objects;
    }

    while (pos < s.size()) {
        objects.push_back(parse_json_object(s, pos));

        skip_ws(s, pos);

        if (pos < s.size() && s[pos] == ',') {
            ++pos;
            continue;
        }

        if (pos < s.size() && s[pos] == ']') {
            ++pos;
            skip_ws(s, pos);

            if (pos != s.size()) {
                throw std::runtime_error("Unexpected trailing data after JSON array.");
            }

            return objects;
        }

        throw std::runtime_error("Malformed JSON array.");
    }

    throw std::runtime_error("Unterminated JSON array.");
}

static std::string get_required(const JsonObject& obj, const std::string& key) {
    auto it = obj.find(key);

    if (it == obj.end()) {
        throw std::runtime_error("KAT case missing field: " + key);
    }

    return it->second;
}

static std::string get_optional(const JsonObject& obj, const std::string& key, const std::string& fallback) {
    auto it = obj.find(key);

    if (it == obj.end()) {
        return fallback;
    }

    return it->second;
}

static std::string lower_copy(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    return s;
}

static Bytes encrypt_classic_no_padding(
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv,
    const Bytes& plaintext
) {
    std::string out;

    if (mode == "ecb") {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKey(key.data(), key.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "cbc") {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "cfb") {
        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "ofb") {
        CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "ctr") {
        CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else {
        throw std::runtime_error("Unsupported KAT classic mode: " + mode);
    }

    return Bytes(out.begin(), out.end());
}

static Bytes decrypt_classic_no_padding(
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv,
    const Bytes& ciphertext
) {
    std::string out;

    if (mode == "ecb") {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKey(key.data(), key.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "cbc") {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "cfb") {
        CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "ofb") {
        CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else if (mode == "ctr") {
        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );
    } else {
        throw std::runtime_error("Unsupported KAT classic mode: " + mode);
    }

    return Bytes(out.begin(), out.end());
}

static void gcm_encrypt_kat(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& plaintext,
    size_t tag_len,
    Bytes& ciphertext,
    Bytes& tag
) {
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    std::string out;

    CryptoPP::AuthenticatedEncryptionFilter ef(
        enc,
        new CryptoPP::StringSink(out),
        false,
        static_cast<int>(tag_len)
    );

    if (!aad.empty()) {
        ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }

    ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!plaintext.empty()) {
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    }

    ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    if (out.size() < tag_len) {
        throw std::runtime_error("GCM KAT output shorter than tag length.");
    }

    const size_t ct_len = out.size() - tag_len;

    ciphertext.assign(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(ct_len));
    tag.assign(out.begin() + static_cast<std::ptrdiff_t>(ct_len), out.end());
}

static Bytes gcm_decrypt_kat(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& ciphertext,
    const Bytes& tag
) {
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    std::string input;
    input.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    input.append(reinterpret_cast<const char*>(tag.data()), tag.size());

    std::string out;

    CryptoPP::AuthenticatedDecryptionFilter df(
        dec,
        new CryptoPP::StringSink(out),
        CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION |
            CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END,
        static_cast<int>(tag.size())
    );

    if (!aad.empty()) {
        df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }

    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!input.empty()) {
        df.ChannelPut(
            CryptoPP::DEFAULT_CHANNEL,
            reinterpret_cast<const CryptoPP::byte*>(input.data()),
            input.size()
        );
    }

    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    return Bytes(out.begin(), out.end());
}

template <int TAG_SIZE>
static void ccm_encrypt_kat_template(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& plaintext,
    Bytes& ciphertext,
    Bytes& tag
) {
    typename CryptoPP::CCM<CryptoPP::AES, TAG_SIZE>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    enc.SpecifyDataLengths(
        static_cast<CryptoPP::lword>(aad.size()),
        static_cast<CryptoPP::lword>(plaintext.size()),
        0
    );

    std::string out;

    CryptoPP::AuthenticatedEncryptionFilter ef(
        enc,
        new CryptoPP::StringSink(out),
        false,
        TAG_SIZE
    );

    if (!aad.empty()) {
        ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }

    ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!plaintext.empty()) {
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
    }

    ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    const size_t ct_len = out.size() - TAG_SIZE;

    ciphertext.assign(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(ct_len));
    tag.assign(out.begin() + static_cast<std::ptrdiff_t>(ct_len), out.end());
}

template <int TAG_SIZE>
static Bytes ccm_decrypt_kat_template(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& ciphertext,
    const Bytes& tag
) {
    typename CryptoPP::CCM<CryptoPP::AES, TAG_SIZE>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());

    dec.SpecifyDataLengths(
        static_cast<CryptoPP::lword>(aad.size()),
        static_cast<CryptoPP::lword>(ciphertext.size()),
        0
    );

    std::string input;
    input.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    input.append(reinterpret_cast<const char*>(tag.data()), tag.size());

    std::string out;

    CryptoPP::AuthenticatedDecryptionFilter df(
        dec,
        new CryptoPP::StringSink(out),
        CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION |
            CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_END,
        TAG_SIZE
    );

    if (!aad.empty()) {
        df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
    }

    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);

    if (!input.empty()) {
        df.ChannelPut(
            CryptoPP::DEFAULT_CHANNEL,
            reinterpret_cast<const CryptoPP::byte*>(input.data()),
            input.size()
        );
    }

    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

    return Bytes(out.begin(), out.end());
}

static void ccm_encrypt_kat(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& plaintext,
    size_t tag_len,
    Bytes& ciphertext,
    Bytes& tag
) {
    switch (tag_len) {
        case 4: ccm_encrypt_kat_template<4>(key, nonce, aad, plaintext, ciphertext, tag); return;
        case 6: ccm_encrypt_kat_template<6>(key, nonce, aad, plaintext, ciphertext, tag); return;
        case 8: ccm_encrypt_kat_template<8>(key, nonce, aad, plaintext, ciphertext, tag); return;
        case 10: ccm_encrypt_kat_template<10>(key, nonce, aad, plaintext, ciphertext, tag); return;
        case 12: ccm_encrypt_kat_template<12>(key, nonce, aad, plaintext, ciphertext, tag); return;
        case 14: ccm_encrypt_kat_template<14>(key, nonce, aad, plaintext, ciphertext, tag); return;
        case 16: ccm_encrypt_kat_template<16>(key, nonce, aad, plaintext, ciphertext, tag); return;
        default:
            throw std::runtime_error("Unsupported CCM tag length in KAT. Expected 4, 6, 8, 10, 12, 14, or 16.");
    }
}

static Bytes ccm_decrypt_kat(
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& aad,
    const Bytes& ciphertext,
    const Bytes& tag
) {
    switch (tag.size()) {
        case 4: return ccm_decrypt_kat_template<4>(key, nonce, aad, ciphertext, tag);
        case 6: return ccm_decrypt_kat_template<6>(key, nonce, aad, ciphertext, tag);
        case 8: return ccm_decrypt_kat_template<8>(key, nonce, aad, ciphertext, tag);
        case 10: return ccm_decrypt_kat_template<10>(key, nonce, aad, ciphertext, tag);
        case 12: return ccm_decrypt_kat_template<12>(key, nonce, aad, ciphertext, tag);
        case 14: return ccm_decrypt_kat_template<14>(key, nonce, aad, ciphertext, tag);
        case 16: return ccm_decrypt_kat_template<16>(key, nonce, aad, ciphertext, tag);
        default:
            throw std::runtime_error("Unsupported CCM tag length in KAT.");
    }
}

static bool run_one_kat_case(const JsonObject& tc, std::string& reason) {
    const std::string name = get_optional(tc, "name", "(unnamed)");
    const std::string mode = lower_copy(get_required(tc, "mode"));

    try {
        const Bytes key = hex_decode(get_required(tc, "key"));
        const Bytes pt = hex_decode(get_required(tc, "pt"));
        const Bytes expected_ct = hex_decode(get_required(tc, "ct"));

        if (mode == "ecb" || mode == "cbc" || mode == "cfb" || mode == "ofb" || mode == "ctr") {
            Bytes iv;

            if (mode != "ecb") {
                iv = hex_decode(get_required(tc, "iv"));
            }

            const Bytes actual_ct = encrypt_classic_no_padding(mode, key, iv, pt);
            const Bytes actual_pt = decrypt_classic_no_padding(mode, key, iv, expected_ct);

            if (actual_ct != expected_ct) {
                reason = "ciphertext mismatch. got=" + hex_encode(actual_ct) + " expected=" + hex_encode(expected_ct);
                return false;
            }

            if (actual_pt != pt) {
                reason = "decryption plaintext mismatch.";
                return false;
            }

            return true;
        }

        if (mode == "gcm") {
            const Bytes nonce = hex_decode(get_required(tc, "nonce"));
            const Bytes aad = hex_decode(get_optional(tc, "aad", ""));
            const Bytes expected_tag = hex_decode(get_required(tc, "tag"));
            const size_t tag_len = expected_tag.size();

            Bytes actual_ct;
            Bytes actual_tag;

            gcm_encrypt_kat(key, nonce, aad, pt, tag_len, actual_ct, actual_tag);
            const Bytes actual_pt = gcm_decrypt_kat(key, nonce, aad, expected_ct, expected_tag);

            if (actual_ct != expected_ct) {
                reason = "GCM ciphertext mismatch. got=" + hex_encode(actual_ct) + " expected=" + hex_encode(expected_ct);
                return false;
            }

            if (actual_tag != expected_tag) {
                reason = "GCM tag mismatch. got=" + hex_encode(actual_tag) + " expected=" + hex_encode(expected_tag);
                return false;
            }

            if (actual_pt != pt) {
                reason = "GCM decryption plaintext mismatch.";
                return false;
            }

            return true;
        }

        if (mode == "ccm") {
            const Bytes nonce = hex_decode(get_required(tc, "nonce"));
            const Bytes aad = hex_decode(get_optional(tc, "aad", ""));
            const Bytes expected_tag = hex_decode(get_required(tc, "tag"));
            const size_t tag_len = expected_tag.size();

            Bytes actual_ct;
            Bytes actual_tag;

            ccm_encrypt_kat(key, nonce, aad, pt, tag_len, actual_ct, actual_tag);
            const Bytes actual_pt = ccm_decrypt_kat(key, nonce, aad, expected_ct, expected_tag);

            if (actual_ct != expected_ct) {
                reason = "CCM ciphertext mismatch. got=" + hex_encode(actual_ct) + " expected=" + hex_encode(expected_ct);
                return false;
            }

            if (actual_tag != expected_tag) {
                reason = "CCM tag mismatch. got=" + hex_encode(actual_tag) + " expected=" + hex_encode(expected_tag);
                return false;
            }

            if (actual_pt != pt) {
                reason = "CCM decryption plaintext mismatch.";
                return false;
            }

            return true;
        }

        reason = "unsupported KAT mode: " + mode;
        return false;
    } catch (const std::exception& e) {
        reason = std::string("exception in case ") + name + ": " + e.what();
        return false;
    }
}

void command_kat(const std::map<std::string, std::string>& opts) {
    const std::string path = require_option(opts, "kat");
    const std::string json = read_text_file(path);

    const std::vector<JsonObject> cases = parse_json_array_of_objects(json);

    if (cases.empty()) {
        throw std::runtime_error("KAT file contains no test cases.");
    }

    size_t pass = 0;
    size_t fail = 0;

    std::cout << "Running AES KAT file: " << path << "\n";
    std::cout << "Total cases: " << cases.size() << "\n\n";

    for (size_t i = 0; i < cases.size(); ++i) {
        const std::string name = get_optional(cases[i], "name", "case-" + std::to_string(i));
        std::string reason;

        const bool ok = run_one_kat_case(cases[i], reason);

        if (ok) {
            ++pass;
            std::cout << "[PASS] " << name << "\n";
        } else {
            ++fail;
            std::cout << "[FAIL] " << name << " :: " << reason << "\n";
        }
    }

    std::cout << "\nKAT summary: pass=" << pass << ", fail=" << fail << ", total=" << cases.size() << "\n";

    if (fail != 0) {
        throw std::runtime_error("KAT failed.");
    }
}