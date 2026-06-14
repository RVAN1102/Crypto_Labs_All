#include "hashtool/length_extension.hpp"

#include "hashtool/file_utils.hpp"
#include "hashtool/hash.hpp"
#include "hashtool/mac.hpp"

#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

namespace hashtool {

namespace {

constexpr std::array<std::uint32_t, 64> K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

std::uint32_t rotr(std::uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32U - n));
}

std::uint32_t load_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24U) |
        (static_cast<std::uint32_t>(p[1]) << 16U) |
        (static_cast<std::uint32_t>(p[2]) << 8U) |
        static_cast<std::uint32_t>(p[3]);
}

void store_be32(std::uint32_t value, Bytes& out) {
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void store_be64(std::uint64_t value, Bytes& out) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

class Sha256Continuation {
public:
    Sha256Continuation(const std::array<std::uint32_t, 8>& state, std::uint64_t total_bytes)
        : state_(state), total_bytes_(total_bytes) {}

    void update(const Bytes& data) {
        for (const auto byte : data) {
            buffer_[buffer_size_++] = byte;
            ++total_bytes_;
            if (buffer_size_ == buffer_.size()) {
                compress(buffer_.data());
                buffer_size_ = 0;
            }
        }
    }

    Bytes final() {
        const std::uint64_t original_total = total_bytes_;
        buffer_[buffer_size_++] = 0x80U;
        if (buffer_size_ > 56) {
            while (buffer_size_ < 64) {
                buffer_[buffer_size_++] = 0;
            }
            compress(buffer_.data());
            buffer_size_ = 0;
        }
        while (buffer_size_ < 56) {
            buffer_[buffer_size_++] = 0;
        }

        const std::uint64_t bit_length = original_total * 8ULL;
        for (int shift = 56; shift >= 0; shift -= 8) {
            buffer_[buffer_size_++] = static_cast<std::uint8_t>((bit_length >> shift) & 0xffU);
        }
        compress(buffer_.data());
        buffer_size_ = 0;

        Bytes digest;
        digest.reserve(32);
        for (const auto word : state_) {
            store_be32(word, digest);
        }
        return digest;
    }

private:
    void compress(const std::uint8_t block[64]) {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i) {
            w[i] = load_be32(block + i * 4);
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];

        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = h + s1 + ch + K[i] + w[i];
            const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffer_size_ = 0;
    std::uint64_t total_bytes_ = 0;
};

Bytes text_bytes(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

bool load_or_create_demo_key(const std::filesystem::path& path, Bytes& key, std::string& error) {
    if (std::filesystem::exists(path)) {
        return read_binary_file(path.string(), key, error);
    }

    key.assign(16, 0);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        error = "OpenSSL RAND_bytes failed for demo key";
        return false;
    }
    return write_binary_file(path.string(), key, error);
}

bool sha256_bytes(const Bytes& input, Bytes& digest, std::string& error) {
    HashAlgorithm algorithm;
    if (!parse_hash_algorithm("sha256", algorithm)) {
        error = "internal sha256 algorithm unavailable";
        return false;
    }
    return hash_bytes(algorithm, input, 0, digest, error);
}

Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

bool write_ascii(const std::filesystem::path& path, const std::string& text, std::string& error) {
    return write_text_file(path.string(), text, error);
}

std::string pass_fail(bool ok) {
    return ok ? "PASS" : "FAIL";
}

} // namespace

Bytes sha256_glue_padding(std::uint64_t message_length_bytes) {
    Bytes padding;
    padding.push_back(0x80U);
    while (((message_length_bytes + padding.size()) % 64U) != 56U) {
        padding.push_back(0);
    }
    store_be64(message_length_bytes * 8ULL, padding);
    return padding;
}

bool sha256_length_extend(
    const Bytes& original_digest,
    std::uint64_t processed_length_before_extension,
    const Bytes& extension,
    Bytes& forged_digest,
    std::string& error) {
    if (original_digest.size() != 32) {
        error = "SHA-256 digest must be 32 bytes";
        return false;
    }

    std::array<std::uint32_t, 8> state{};
    for (std::size_t i = 0; i < state.size(); ++i) {
        state[i] = load_be32(original_digest.data() + i * 4);
    }

    Sha256Continuation sha(state, processed_length_before_extension);
    sha.update(extension);
    forged_digest = sha.final();
    return true;
}

bool run_length_extension_demo(
    const std::string& out_dir,
    LengthExtensionDemoResult& result,
    std::string& output,
    std::string& error) {
    const std::filesystem::path dir(out_dir);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        error = "cannot create length-extension demo directory";
        return false;
    }

    const std::string original_text = "comment=10&uid=1001&role=user";
    const std::string extension_text = "&role=admin";
    const Bytes original_message = text_bytes(original_text);
    const Bytes extension = text_bytes(extension_text);

    Bytes key;
    if (!load_or_create_demo_key(dir / "demo_key.bin", key, error)) {
        return false;
    }

    const std::size_t guessed_key_length = key.size();
    const Bytes key_plus_original = concat(key, original_message);

    Bytes original_mac;
    if (!sha256_bytes(key_plus_original, original_mac, error)) {
        return false;
    }

    const Bytes glue_padding = sha256_glue_padding(static_cast<std::uint64_t>(guessed_key_length + original_message.size()));
    Bytes forged_message = original_message;
    forged_message.insert(forged_message.end(), glue_padding.begin(), glue_padding.end());
    forged_message.insert(forged_message.end(), extension.begin(), extension.end());

    Bytes forged_mac;
    const std::uint64_t processed_before_extension =
        static_cast<std::uint64_t>(guessed_key_length + original_message.size() + glue_padding.size());
    if (!sha256_length_extend(original_mac, processed_before_extension, extension, forged_mac, error)) {
        return false;
    }

    Bytes naive_original_check;
    Bytes naive_forged_check;
    if (!sha256_bytes(key_plus_original, naive_original_check, error)) {
        return false;
    }
    if (!sha256_bytes(concat(key, forged_message), naive_forged_check, error)) {
        return false;
    }

    HashAlgorithm sha256;
    if (!parse_hash_algorithm("sha256", sha256)) {
        error = "internal sha256 algorithm unavailable";
        return false;
    }
    Bytes hmac_forged;
    if (!hmac_bytes(sha256, key, forged_message, hmac_forged, error)) {
        return false;
    }

    result.naive_original_verify = naive_original_check == original_mac;
    result.naive_forged_verify = naive_forged_check == forged_mac;
    result.hmac_forged_verify = hmac_forged == forged_mac;
    result.original_mac_hex = hex_encode(original_mac);
    result.forged_mac_hex = hex_encode(forged_mac);
    result.guessed_key_length = guessed_key_length;
    result.glue_padding_size = glue_padding.size();

    if (!write_ascii(dir / "original_message.txt", original_text + "\n", error) ||
        !write_ascii(dir / "original_mac.txt", result.original_mac_hex + "\n", error) ||
        !write_binary_file((dir / "forged_message.bin").string(), forged_message, error) ||
        !write_ascii(dir / "forged_mac.txt", result.forged_mac_hex + "\n", error)) {
        return false;
    }

    std::ostringstream diagram;
    diagram << "MAC construction: SHA256(key || message)\n";
    diagram << "guessed_key_length_bytes=" << guessed_key_length << "\n";
    diagram << "original_message_length_bytes=" << original_message.size() << "\n";
    diagram << "glue_padding_length_bytes=" << glue_padding.size() << "\n";
    diagram << "extension=" << extension_text << "\n";
    diagram << "forged_message = original_message || glue_padding || extension\n";
    diagram << "glue_padding_hex=" << hex_encode(glue_padding) << "\n";
    diagram << "processed_before_extension_bytes=" << processed_before_extension << "\n";
    if (!write_ascii(dir / "padding_diagram.txt", diagram.str(), error)) {
        return false;
    }

    std::ostringstream verification;
    verification << "naive_original_verify=" << pass_fail(result.naive_original_verify) << "\n";
    verification << "naive_forged_verify=" << pass_fail(result.naive_forged_verify) << "\n";
    verification << "hmac_forged_verify=" << pass_fail(result.hmac_forged_verify) << "\n";
    if (!write_ascii(dir / "verification_result.txt", verification.str(), error)) {
        return false;
    }

    std::ostringstream readme;
    readme << "# Length-Extension Demo\n\n";
    readme << "This is an offline defensive lab demo only. It does not target any live service, network endpoint, or third-party system.\n\n";
    readme << "The intentionally insecure MAC is `SHA256(key || message)`. SHA-256 is a Merkle-Damgard hash: it processes fixed-size blocks and its final digest is the internal chaining state after padding has been processed. If an attacker knows the digest and can guess the length of the unknown prefix key, the attacker can reconstruct the exact glue padding that SHA-256 added after `key || message` and continue hashing extra bytes from that exposed state.\n\n";
    readme << "Glue padding is the SHA-256 padding bytes for the hidden `key || original_message`: a `0x80` byte, enough zero bytes to align the length field, and the original bit length encoded as a 64-bit big-endian integer. The forged visible message is `original_message || glue_padding || extension`; the secret key is not included in the file, but the verifier hashes `key || forged_message`, which recreates the same block stream.\n\n";
    readme << "Only the key length is needed because SHA-256 padding depends on message length, not key contents. The continuation helper starts from `original_mac` as the internal state and hashes the extension with the byte counter set to the length after glue padding.\n\n";
    readme << "HMAC prevents this attack because it does not expose the raw internal state of `SHA256(key || message)`. It hashes with separate inner and outer keyed domains, so continuing from an observed HMAC value does not produce a valid HMAC for an extended message.\n\n";
    readme << "Generated files:\n";
    readme << "- `demo_key.bin`: local test key only\n";
    readme << "- `original_message.txt`\n";
    readme << "- `original_mac.txt`\n";
    readme << "- `forged_message.bin`\n";
    readme << "- `forged_mac.txt`\n";
    readme << "- `padding_diagram.txt`\n";
    readme << "- `verification_result.txt`\n";
    if (!write_ascii(dir / "README.md", readme.str(), error)) {
        return false;
    }

    output = "Length-extension demo complete: " + dir.string() + "\n" + verification.str();
    return result.naive_original_verify && result.naive_forged_verify && !result.hmac_forged_verify;
}

} // namespace hashtool

