#include "metadata.hpp"

#include "encoding.hpp"
#include "file_utils.hpp"

#include <stdexcept>

static constexpr int GCM_TAG_SIZE = 16;
static constexpr int GCM_RECOMMENDED_NONCE_SIZE = 12;
static constexpr int AES_IV_SIZE = 16;
static constexpr int CCM_TAG_SIZE = 16;
static constexpr int XTS_TWEAK_SIZE = 16;

static std::string extract_json_string(const std::string& json, const std::string& field) {
    const std::string key = "\"" + field + "\"";
    const size_t key_pos = json.find(key);

    if (key_pos == std::string::npos) {
        throw std::runtime_error("Missing metadata field: " + field);
    }

    const size_t colon_pos = json.find(':', key_pos + key.size());

    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Malformed metadata field: " + field);
    }

    const size_t first_quote = json.find('"', colon_pos + 1);

    if (first_quote == std::string::npos) {
        throw std::runtime_error("Malformed metadata string value: " + field);
    }

    const size_t second_quote = json.find('"', first_quote + 1);

    if (second_quote == std::string::npos) {
        throw std::runtime_error("Malformed metadata string value: " + field);
    }

    return json.substr(first_quote + 1, second_quote - first_quote - 1);
}

GcmMetadata::GcmMetadata()
    : key_bits_(0) {
}

void GcmMetadata::set_ciphertext_file(const std::string& value) {
    ciphertext_file_ = value;
}

void GcmMetadata::set_key_bits(int value) {
    key_bits_ = value;
}

void GcmMetadata::set_nonce(const Bytes& value) {
    if (value.size() != static_cast<size_t>(GCM_RECOMMENDED_NONCE_SIZE)) {
        throw std::runtime_error("Invalid GCM nonce length in metadata.");
    }

    nonce_ = value;
}

void GcmMetadata::set_tag(const Bytes& value) {
    if (value.size() != static_cast<size_t>(GCM_TAG_SIZE)) {
        throw std::runtime_error("Invalid GCM tag length in metadata.");
    }

    tag_ = value;
}

void GcmMetadata::set_aad(const Bytes& value) {
    aad_ = value;
}

const Bytes& GcmMetadata::nonce() const {
    return nonce_;
}

const Bytes& GcmMetadata::tag() const {
    return tag_;
}

std::string GcmMetadata::to_json() const {
    std::string json;

    json += "{\n";
    json += "  \"alg\": \"AES-" + std::to_string(key_bits_) + "-GCM\",\n";
    json += "  \"mode\": \"gcm\",\n";
    json += "  \"key_bits\": " + std::to_string(key_bits_) + ",\n";
    json += "  \"nonce_hex\": \"" + hex_encode(nonce_) + "\",\n";
    json += "  \"tag_hex\": \"" + hex_encode(tag_) + "\",\n";
    json += "  \"tag_len\": " + std::to_string(GCM_TAG_SIZE) + ",\n";
    json += "  \"aad_hex\": \"" + hex_encode(aad_) + "\",\n";
    json += "  \"ciphertext_file\": \"" + json_escape(ciphertext_file_) + "\"\n";
    json += "}\n";

    return json;
}

GcmMetadata GcmMetadata::from_json(const std::string& json) {
    const std::string mode = extract_json_string(json, "mode");

    if (mode != "gcm") {
        throw std::runtime_error("Metadata mode mismatch. Expected gcm.");
    }

    GcmMetadata meta;
    meta.set_nonce(hex_decode(extract_json_string(json, "nonce_hex")));
    meta.set_tag(hex_decode(extract_json_string(json, "tag_hex")));

    return meta;
}

CcmMetadata::CcmMetadata()
    : key_bits_(0) {
}

void CcmMetadata::set_ciphertext_file(const std::string& value) {
    ciphertext_file_ = value;
}

void CcmMetadata::set_key_bits(int value) {
    key_bits_ = value;
}

void CcmMetadata::set_nonce(const Bytes& value) {
    if (value.size() < 7 || value.size() > 13) {
        throw std::runtime_error("Invalid CCM nonce length in metadata.");
    }

    nonce_ = value;
}

void CcmMetadata::set_tag(const Bytes& value) {
    if (value.size() != static_cast<size_t>(CCM_TAG_SIZE)) {
        throw std::runtime_error("Invalid CCM tag length in metadata.");
    }

    tag_ = value;
}

void CcmMetadata::set_aad(const Bytes& value) {
    aad_ = value;
}

const Bytes& CcmMetadata::nonce() const {
    return nonce_;
}

const Bytes& CcmMetadata::tag() const {
    return tag_;
}

std::string CcmMetadata::to_json() const {
    std::string json;

    json += "{\n";
    json += "  \"alg\": \"AES-" + std::to_string(key_bits_) + "-CCM\",\n";
    json += "  \"mode\": \"ccm\",\n";
    json += "  \"key_bits\": " + std::to_string(key_bits_) + ",\n";
    json += "  \"nonce_hex\": \"" + hex_encode(nonce_) + "\",\n";
    json += "  \"tag_hex\": \"" + hex_encode(tag_) + "\",\n";
    json += "  \"tag_len\": " + std::to_string(CCM_TAG_SIZE) + ",\n";
    json += "  \"aad_hex\": \"" + hex_encode(aad_) + "\",\n";
    json += "  \"ciphertext_file\": \"" + json_escape(ciphertext_file_) + "\"\n";
    json += "}\n";

    return json;
}

CcmMetadata CcmMetadata::from_json(const std::string& json) {
    const std::string mode = extract_json_string(json, "mode");

    if (mode != "ccm") {
        throw std::runtime_error("Metadata mode mismatch. Expected ccm.");
    }

    CcmMetadata meta;
    meta.set_nonce(hex_decode(extract_json_string(json, "nonce_hex")));
    meta.set_tag(hex_decode(extract_json_string(json, "tag_hex")));

    return meta;
}

XtsMetadata::XtsMetadata()
    : key_bits_(0) {
}

void XtsMetadata::set_ciphertext_file(const std::string& value) {
    ciphertext_file_ = value;
}

void XtsMetadata::set_key_bits(int value) {
    if (value != 256 && value != 512) {
        throw std::runtime_error("Invalid XTS key material size in metadata. Expected 256 or 512 bits.");
    }

    key_bits_ = value;
}

void XtsMetadata::set_tweak(const Bytes& value) {
    if (value.size() != static_cast<size_t>(XTS_TWEAK_SIZE)) {
        throw std::runtime_error("Invalid XTS tweak length in metadata.");
    }

    tweak_ = value;
}

const Bytes& XtsMetadata::tweak() const {
    return tweak_;
}

std::string XtsMetadata::to_json() const {
    std::string json;

    json += "{\n";
    json += "  \"alg\": \"AES-XTS\",\n";
    json += "  \"mode\": \"xts\",\n";
    json += "  \"key_material_bits\": " + std::to_string(key_bits_) + ",\n";
    json += "  \"tweak_hex\": \"" + hex_encode(tweak_) + "\",\n";
    json += "  \"ciphertext_file\": \"" + json_escape(ciphertext_file_) + "\"\n";
    json += "}\n";

    return json;
}

XtsMetadata XtsMetadata::from_json(const std::string& json) {
    const std::string mode = extract_json_string(json, "mode");

    if (mode != "xts") {
        throw std::runtime_error("Metadata mode mismatch. Expected xts.");
    }

    XtsMetadata meta;
    meta.set_tweak(hex_decode(extract_json_string(json, "tweak_hex")));

    return meta;
}

ClassicMetadata::ClassicMetadata()
    : key_bits_(0) {
}

void ClassicMetadata::set_ciphertext_file(const std::string& value) {
    ciphertext_file_ = value;
}

void ClassicMetadata::set_mode(const std::string& value) {
    if (value != "ecb" &&
        value != "cbc" &&
        value != "cfb" &&
        value != "ofb" &&
        value != "ctr") {
        throw std::runtime_error("Invalid classic AES mode in metadata: " + value);
    }

    mode_ = value;
}

void ClassicMetadata::set_key_bits(int value) {
    key_bits_ = value;
}

void ClassicMetadata::set_iv(const Bytes& value) {
    if (mode_ == "ecb") {
        if (!value.empty()) {
            throw std::runtime_error("ECB metadata must not contain IV.");
        }

        iv_.clear();
        return;
    }

    if (value.size() != static_cast<size_t>(AES_IV_SIZE)) {
        throw std::runtime_error("Invalid AES IV length in metadata.");
    }

    iv_ = value;
}

const std::string& ClassicMetadata::mode() const {
    return mode_;
}

const Bytes& ClassicMetadata::iv() const {
    return iv_;
}

std::string ClassicMetadata::to_json() const {
    std::string json;

    json += "{\n";
    json += "  \"alg\": \"AES-" + std::to_string(key_bits_) + "-" + mode_ + "\",\n";
    json += "  \"mode\": \"" + mode_ + "\",\n";
    json += "  \"key_bits\": " + std::to_string(key_bits_) + ",\n";
    json += "  \"iv_hex\": \"" + hex_encode(iv_) + "\",\n";
    json += "  \"ciphertext_file\": \"" + json_escape(ciphertext_file_) + "\"\n";
    json += "}\n";

    return json;
}

ClassicMetadata ClassicMetadata::from_json(const std::string& json) {
    ClassicMetadata meta;

    const std::string mode = extract_json_string(json, "mode");
    meta.set_mode(mode);

    const std::string iv_hex = extract_json_string(json, "iv_hex");

    if (mode == "ecb") {
        if (!iv_hex.empty()) {
            throw std::runtime_error("ECB metadata must not contain IV.");
        }

        meta.set_iv({});
    } else {
        meta.set_iv(hex_decode(iv_hex));
    }

    return meta;
}

void write_gcm_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& tag,
    const Bytes& aad
) {
    GcmMetadata meta;

    meta.set_ciphertext_file(ciphertext_file);
    meta.set_key_bits(static_cast<int>(key.size() * 8));
    meta.set_nonce(nonce);
    meta.set_tag(tag);
    meta.set_aad(aad);

    write_text_file(meta_path, meta.to_json());
}

void write_ccm_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& tag,
    const Bytes& aad
) {
    CcmMetadata meta;

    meta.set_ciphertext_file(ciphertext_file);
    meta.set_key_bits(static_cast<int>(key.size() * 8));
    meta.set_nonce(nonce);
    meta.set_tag(tag);
    meta.set_aad(aad);

    write_text_file(meta_path, meta.to_json());
}

void write_xts_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const Bytes& key,
    const Bytes& tweak
) {
    XtsMetadata meta;

    meta.set_ciphertext_file(ciphertext_file);
    meta.set_key_bits(static_cast<int>(key.size() * 8));
    meta.set_tweak(tweak);

    write_text_file(meta_path, meta.to_json());
}

void write_classic_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv
) {
    ClassicMetadata meta;

    meta.set_ciphertext_file(ciphertext_file);
    meta.set_mode(mode);
    meta.set_key_bits(static_cast<int>(key.size() * 8));
    meta.set_iv(iv);

    write_text_file(meta_path, meta.to_json());
}