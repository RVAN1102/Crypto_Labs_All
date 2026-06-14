#include "nonce_registry.hpp"

#include "encoding.hpp"

#include <filters.h>
#include <sha.h>

#include <fstream>
#include <stdexcept>
#include <string>

std::string default_nonce_registry_path() {
    return ".aestool_nonce_registry.jsonl";
}

static std::string sha256_hex(const Bytes& data) {
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource ss(
        data.data(),
        data.size(),
        true,
        new CryptoPP::HashFilter(
            hash,
            new CryptoPP::StringSink(digest)
        )
    );

    Bytes digest_bytes(digest.begin(), digest.end());
    return hex_encode(digest_bytes);
}

static std::string make_registry_record(
    const std::string& mode,
    const std::string& key_sha256,
    const std::string& nonce_hex
) {
    std::string line;

    line += "{\"mode\":\"";
    line += mode;
    line += "\",\"key_sha256\":\"";
    line += key_sha256;
    line += "\",\"nonce_or_iv_hex\":\"";
    line += nonce_hex;
    line += "\"}";

    return line;
}

void check_and_record_nonce_use(
    const std::string& mode,
    const Bytes& key,
    const Bytes& nonce_or_iv,
    const std::string& registry_path
) {
    if (mode != "gcm" && mode != "ctr" && mode != "ccm") {
        return;
    }

    const std::string key_sha256 = sha256_hex(key);
    const std::string nonce_hex = hex_encode(nonce_or_iv);
    const std::string current_record = make_registry_record(mode, key_sha256, nonce_hex);

    {
        std::ifstream in(registry_path, std::ios::binary);

        if (in) {
            std::string line;

            while (std::getline(in, line)) {
                if (line == current_record) {
                    throw std::runtime_error(
                        "Nonce/IV reuse detected for mode " + mode +
                        ". The same key fingerprint and nonce/IV were already used. Operation rejected."
                    );
                }
            }
        }
    }

    {
        std::ofstream out(registry_path, std::ios::binary | std::ios::app);

        if (!out) {
            throw std::runtime_error("Cannot open nonce registry for writing: " + registry_path);
        }

        out << current_record << "\n";

        if (!out) {
            throw std::runtime_error("Failed to update nonce registry: " + registry_path);
        }
    }
}