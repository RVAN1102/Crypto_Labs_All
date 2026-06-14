#pragma once

#include "encoding.hpp"

#include <string>

class GcmMetadata {
public:
    GcmMetadata();

    void set_ciphertext_file(const std::string& value);
    void set_key_bits(int value);
    void set_nonce(const Bytes& value);
    void set_tag(const Bytes& value);
    void set_aad(const Bytes& value);

    const Bytes& nonce() const;
    const Bytes& tag() const;

    std::string to_json() const;

    static GcmMetadata from_json(const std::string& json);

private:
    std::string ciphertext_file_;
    int key_bits_;
    Bytes nonce_;
    Bytes tag_;
    Bytes aad_;
};

class CcmMetadata {
public:
    CcmMetadata();

    void set_ciphertext_file(const std::string& value);
    void set_key_bits(int value);
    void set_nonce(const Bytes& value);
    void set_tag(const Bytes& value);
    void set_aad(const Bytes& value);

    const Bytes& nonce() const;
    const Bytes& tag() const;

    std::string to_json() const;

    static CcmMetadata from_json(const std::string& json);

private:
    std::string ciphertext_file_;
    int key_bits_;
    Bytes nonce_;
    Bytes tag_;
    Bytes aad_;
};

class XtsMetadata {
public:
    XtsMetadata();

    void set_ciphertext_file(const std::string& value);
    void set_key_bits(int value);
    void set_tweak(const Bytes& value);

    const Bytes& tweak() const;

    std::string to_json() const;

    static XtsMetadata from_json(const std::string& json);

private:
    std::string ciphertext_file_;
    int key_bits_;
    Bytes tweak_;
};

class ClassicMetadata {
public:
    ClassicMetadata();

    void set_ciphertext_file(const std::string& value);
    void set_mode(const std::string& value);
    void set_key_bits(int value);
    void set_iv(const Bytes& value);

    const std::string& mode() const;
    const Bytes& iv() const;

    std::string to_json() const;

    static ClassicMetadata from_json(const std::string& json);

private:
    std::string ciphertext_file_;
    std::string mode_;
    int key_bits_;
    Bytes iv_;
};

void write_gcm_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& tag,
    const Bytes& aad
);

void write_classic_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const std::string& mode,
    const Bytes& key,
    const Bytes& iv
);

void write_ccm_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& tag,
    const Bytes& aad
);

void write_xts_metadata(
    const std::string& meta_path,
    const std::string& ciphertext_file,
    const Bytes& key,
    const Bytes& tweak
);