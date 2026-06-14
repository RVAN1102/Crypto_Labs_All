#include "envelope.hpp"

#include "aes_gcm.hpp"
#include "random_utils.hpp"
#include "rsa_oaep.hpp"

#include <cctype>
#include <stdexcept>

static constexpr std::size_t AES_256_KEY_SIZE = 32;
static constexpr std::size_t GCM_NONCE_SIZE = 12;
static constexpr std::size_t GCM_TAG_SIZE = 16;

static void skip_ws(const std::string& s, std::size_t& pos) {
    while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) {
        ++pos;
    }
}

static std::string parse_json_string(const std::string& s, std::size_t& pos) {
    skip_ws(s, pos);
    if (pos >= s.size() || s[pos] != '"') {
        throw std::runtime_error("Malformed JSON string.");
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
                throw std::runtime_error("Malformed JSON escape.");
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
                throw std::runtime_error("Unsupported JSON escape.");
            }
        } else {
            out += c;
        }
    }

    throw std::runtime_error("Unterminated JSON string.");
}

static std::string raw_json_value(const std::string& json, const std::string& field) {
    const std::string key = "\"" + field + "\"";
    const std::size_t key_pos = json.find(key);

    if (key_pos == std::string::npos) {
        throw std::runtime_error("Missing envelope field: " + field);
    }

    std::size_t pos = json.find(':', key_pos + key.size());
    if (pos == std::string::npos) {
        throw std::runtime_error("Malformed envelope field: " + field);
    }

    ++pos;
    skip_ws(json, pos);

    if (pos >= json.size()) {
        throw std::runtime_error("Missing envelope value: " + field);
    }

    if (json[pos] == '"') {
        return parse_json_string(json, pos);
    }

    const std::size_t start = pos;
    while (pos < json.size() && json[pos] != ',' && json[pos] != '}' && !std::isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }

    if (start == pos) {
        throw std::runtime_error("Malformed envelope value: " + field);
    }

    return json.substr(start, pos - start);
}

static int json_int(const std::string& json, const std::string& field) {
    const std::string value = raw_json_value(json, field);
    try {
        return std::stoi(value);
    } catch (...) {
        throw std::runtime_error("Envelope field is not an integer: " + field);
    }
}

static bool json_bool(const std::string& json, const std::string& field) {
    const std::string value = raw_json_value(json, field);
    if (value == "true") {
        return true;
    }
    if (value == "false") {
        return false;
    }
    throw std::runtime_error("Envelope field is not a boolean: " + field);
}

static std::string json_string(const std::string& json, const std::string& field) {
    return raw_json_value(json, field);
}

static void require_equal(const std::string& actual, const std::string& expected, const std::string& field) {
    if (actual != expected) {
        throw std::runtime_error("Unsupported or mismatched envelope field: " + field);
    }
}

static void validate_envelope(const HybridEnvelope& env) {
    if (env.version != 1) {
        throw std::runtime_error("Unsupported envelope version.");
    }

    require_equal(env.envelope_alg, "RSA-OAEP-SHA256+AES-256-GCM", "envelope_alg");
    require_equal(env.key_alg, "RSA-OAEP-SHA256", "key_alg");
    require_equal(env.content_alg, "AES-256-GCM", "content_alg");
    require_equal(env.oaep_hash, "SHA-256", "oaep_hash");
    require_equal(env.ciphertext_mode, "external", "ciphertext_mode");

    if (env.rsa_bits < 3072) {
        throw std::runtime_error("Envelope RSA modulus is too small.");
    }
    if (env.encrypted_key.empty()) {
        throw std::runtime_error("Envelope encrypted AES key is empty.");
    }
    if (env.nonce.size() != GCM_NONCE_SIZE) {
        throw std::runtime_error("Envelope nonce length is invalid.");
    }
    if (env.tag.size() != GCM_TAG_SIZE) {
        throw std::runtime_error("Envelope tag length is invalid.");
    }
    if (env.oaep_label_sha256_hex.size() != 64) {
        throw std::runtime_error("Envelope OAEP label hash is invalid.");
    }
}

std::string HybridEnvelope::to_json() const {
    std::string json;
    json += "{\n";
    json += "  \"version\": " + std::to_string(version) + ",\n";
    json += "  \"envelope_alg\": \"" + envelope_alg + "\",\n";
    json += "  \"key_alg\": \"" + key_alg + "\",\n";
    json += "  \"content_alg\": \"" + content_alg + "\",\n";
    json += "  \"rsa_bits\": " + std::to_string(rsa_bits) + ",\n";
    json += "  \"oaep_hash\": \"" + oaep_hash + "\",\n";
    json += "  \"oaep_label_present\": ";
    json += oaep_label_present ? "true,\n" : "false,\n";
    json += "  \"oaep_label_sha256_hex\": \"" + oaep_label_sha256_hex + "\",\n";
    json += "  \"encrypted_key_hex\": \"" + hex_encode(encrypted_key) + "\",\n";
    json += "  \"nonce_hex\": \"" + hex_encode(nonce) + "\",\n";
    json += "  \"tag_hex\": \"" + hex_encode(tag) + "\",\n";
    json += "  \"ciphertext_mode\": \"" + ciphertext_mode + "\",\n";
    json += "  \"ciphertext_file\": \"" + json_escape(ciphertext_file) + "\"\n";
    json += "}\n";
    return json;
}

HybridEnvelope HybridEnvelope::from_json(const std::string& json) {
    HybridEnvelope env;
    env.version = json_int(json, "version");
    env.envelope_alg = json_string(json, "envelope_alg");
    env.key_alg = json_string(json, "key_alg");
    env.content_alg = json_string(json, "content_alg");
    env.rsa_bits = json_int(json, "rsa_bits");
    env.oaep_hash = json_string(json, "oaep_hash");
    env.oaep_label_present = json_bool(json, "oaep_label_present");
    env.oaep_label_sha256_hex = json_string(json, "oaep_label_sha256_hex");
    env.encrypted_key = hex_decode(json_string(json, "encrypted_key_hex"));
    env.nonce = hex_decode(json_string(json, "nonce_hex"));
    env.tag = hex_decode(json_string(json, "tag_hex"));
    env.ciphertext_mode = json_string(json, "ciphertext_mode");
    env.ciphertext_file = json_string(json, "ciphertext_file");

    validate_envelope(env);
    return env;
}

HybridEncryptResult hybrid_encrypt(
    const Bytes& public_key_der,
    const Bytes& plaintext,
    const Bytes& oaep_label,
    const std::string& ciphertext_file
) {
    const Bytes aes_key = random_bytes(AES_256_KEY_SIZE);
    const Bytes nonce = random_bytes(GCM_NONCE_SIZE);
    const AesGcmCiphertext aes = aes_256_gcm_encrypt(aes_key, nonce, plaintext);

    HybridEncryptResult result;
    result.ciphertext = aes.ciphertext;
    result.envelope.version = 1;
    result.envelope.rsa_bits = rsa_public_key_bits_der(public_key_der);
    result.envelope.oaep_label_present = !oaep_label.empty();
    result.envelope.oaep_label_sha256_hex = sha256_hex(oaep_label);
    result.envelope.encrypted_key = rsa_oaep_sha256_encrypt_der(public_key_der, aes_key, oaep_label);
    result.envelope.nonce = nonce;
    result.envelope.tag = aes.tag;
    result.envelope.ciphertext_file = ciphertext_file;
    validate_envelope(result.envelope);
    return result;
}

Bytes hybrid_decrypt(
    const Bytes& private_key_der,
    const Bytes& ciphertext,
    const HybridEnvelope& envelope,
    const Bytes& oaep_label
) {
    validate_envelope(envelope);

    if (envelope.oaep_label_sha256_hex != sha256_hex(oaep_label)) {
        throw std::runtime_error("OAEP label does not match envelope label hash.");
    }

    if (envelope.oaep_label_present != !oaep_label.empty()) {
        throw std::runtime_error("OAEP label presence does not match envelope metadata.");
    }

    const int private_bits = rsa_private_key_bits_der(private_key_der);
    if (private_bits != envelope.rsa_bits) {
        throw std::runtime_error("RSA private key size does not match envelope metadata.");
    }

    const Bytes aes_key = rsa_oaep_sha256_decrypt_der(
        private_key_der,
        envelope.encrypted_key,
        oaep_label
    );

    if (aes_key.size() != AES_256_KEY_SIZE) {
        throw std::runtime_error("Decrypted envelope AES key has invalid length.");
    }

    return aes_256_gcm_decrypt(aes_key, envelope.nonce, ciphertext, envelope.tag);
}
