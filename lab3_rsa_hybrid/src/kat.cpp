#include "kat.hpp"

#include "cli.hpp"
#include "encoding.hpp"
#include "envelope.hpp"
#include "file_utils.hpp"
#include "rsa_oaep.hpp"

#include <cctype>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

using JsonObject = std::map<std::string, std::string>;

static void skip_ws(const std::string& s, std::size_t& pos) {
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) {
        ++pos;
    }
}

static void expect_char(const std::string& s, std::size_t& pos, char expected) {
    skip_ws(s, pos);
    if (pos >= s.size() || s[pos] != expected) {
        throw std::runtime_error(std::string("Malformed KAT JSON. Expected '") + expected + "'.");
    }
    ++pos;
}

static std::string parse_json_string(const std::string& s, std::size_t& pos) {
    skip_ws(s, pos);
    if (pos >= s.size() || s[pos] != '"') {
        throw std::runtime_error("Malformed KAT JSON. Expected string.");
    }

    ++pos;
    std::string out;

    while (pos < s.size()) {
        const char c = s[pos++];
        if (c == '"') {
            return out;
        }
        if (c == '\\') {
            if (pos >= s.size()) {
                throw std::runtime_error("Malformed KAT JSON escape.");
            }
            const char e = s[pos++];
            if (e == '"' || e == '\\' || e == '/') {
                out += e;
            } else if (e == 'n') {
                out += '\n';
            } else if (e == 'r') {
                out += '\r';
            } else if (e == 't') {
                out += '\t';
            } else {
                throw std::runtime_error("Unsupported KAT JSON escape.");
            }
        } else {
            out += c;
        }
    }

    throw std::runtime_error("Unterminated KAT JSON string.");
}

static std::string parse_json_value_as_string(const std::string& s, std::size_t& pos) {
    skip_ws(s, pos);
    if (pos < s.size() && s[pos] == '"') {
        return parse_json_string(s, pos);
    }

    const std::size_t start = pos;
    while (pos < s.size() && s[pos] != ',' && s[pos] != '}' && !std::isspace(static_cast<unsigned char>(s[pos]))) {
        ++pos;
    }

    if (start == pos) {
        throw std::runtime_error("Malformed KAT JSON value.");
    }

    return s.substr(start, pos - start);
}

static JsonObject parse_json_object(const std::string& s, std::size_t& pos) {
    JsonObject obj;
    expect_char(s, pos, '{');
    skip_ws(s, pos);

    if (pos < s.size() && s[pos] == '}') {
        ++pos;
        return obj;
    }

    while (pos < s.size()) {
        const std::string key = parse_json_string(s, pos);
        expect_char(s, pos, ':');
        obj[key] = parse_json_value_as_string(s, pos);

        skip_ws(s, pos);
        if (pos < s.size() && s[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < s.size() && s[pos] == '}') {
            ++pos;
            return obj;
        }

        throw std::runtime_error("Malformed KAT JSON object.");
    }

    throw std::runtime_error("Unterminated KAT JSON object.");
}

static std::vector<JsonObject> parse_json_array(const std::string& s) {
    std::vector<JsonObject> out;
    std::size_t pos = 0;
    expect_char(s, pos, '[');
    skip_ws(s, pos);

    if (pos < s.size() && s[pos] == ']') {
        return out;
    }

    while (pos < s.size()) {
        out.push_back(parse_json_object(s, pos));
        skip_ws(s, pos);

        if (pos < s.size() && s[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < s.size() && s[pos] == ']') {
            ++pos;
            skip_ws(s, pos);
            if (pos != s.size()) {
                throw std::runtime_error("Trailing data after KAT JSON array.");
            }
            return out;
        }

        throw std::runtime_error("Malformed KAT JSON array.");
    }

    throw std::runtime_error("Unterminated KAT JSON array.");
}

static std::string get_required(const JsonObject& obj, const std::string& key) {
    const auto it = obj.find(key);
    if (it == obj.end()) {
        throw std::runtime_error("KAT case missing field: " + key);
    }
    return it->second;
}

static std::string get_optional(const JsonObject& obj, const std::string& key, const std::string& fallback) {
    const auto it = obj.find(key);
    return it == obj.end() ? fallback : it->second;
}

static int parse_int_field(const JsonObject& obj, const std::string& key) {
    try {
        return std::stoi(get_required(obj, key));
    } catch (...) {
        throw std::runtime_error("KAT field is not an integer: " + key);
    }
}

static Bytes bytes_from_text(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

static bool run_one_case(const JsonObject& tc, std::string& reason) {
    const std::string kind = get_required(tc, "kind");
    const int bits = parse_int_field(tc, "rsa_bits");
    const Bytes label = bytes_from_text(get_optional(tc, "label_text", ""));
    const Bytes plaintext = hex_decode(get_required(tc, "pt_hex"));

    try {
        const RsaKeyPairDer keys = generate_rsa_keypair_der(bits);

        if (kind == "oaep_roundtrip") {
            const Bytes ciphertext = rsa_oaep_sha256_encrypt_der(keys.public_key_der, plaintext, label);
            const Bytes recovered = rsa_oaep_sha256_decrypt_der(keys.private_key_der, ciphertext, label);

            if (ciphertext.size() != static_cast<std::size_t>(bits / 8)) {
                reason = "RSA ciphertext length mismatch.";
                return false;
            }
            if (recovered != plaintext) {
                reason = "OAEP recovered plaintext mismatch.";
                return false;
            }
            return true;
        }

        if (kind == "hybrid_roundtrip") {
            const HybridEncryptResult sealed = hybrid_encrypt(keys.public_key_der, plaintext, label, "kat.ct");
            const Bytes recovered = hybrid_decrypt(keys.private_key_der, sealed.ciphertext, sealed.envelope, label);

            if (sealed.envelope.rsa_bits != bits) {
                reason = "Envelope rsa_bits mismatch.";
                return false;
            }
            if (sealed.envelope.oaep_hash != "SHA-256") {
                reason = "Envelope OAEP hash mismatch.";
                return false;
            }
            if (recovered != plaintext) {
                reason = "Hybrid recovered plaintext mismatch.";
                return false;
            }
            return true;
        }

        reason = "unsupported KAT kind: " + kind;
        return false;
    } catch (const std::exception& e) {
        reason = e.what();
        return false;
    }
}

void command_kat(const std::map<std::string, std::string>& opts) {
    const std::string path = require_option(opts, "kat");
    const std::vector<JsonObject> cases = parse_json_array(read_text_file(path));

    if (cases.empty()) {
        throw std::runtime_error("KAT file contains no cases.");
    }

    std::size_t pass = 0;
    std::size_t fail = 0;

    std::cout << "Running RSA/hybrid correctness KAT file: " << path << "\n";
    std::cout << "Total cases: " << cases.size() << "\n\n";

    for (std::size_t i = 0; i < cases.size(); ++i) {
        const std::string name = get_optional(cases[i], "name", "case-" + std::to_string(i));
        std::string reason;

        if (run_one_case(cases[i], reason)) {
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
