#include "nonce_registry.hpp"
#include "aes_classic.hpp"
#include "aes_gcm.hpp"
#include "aes_ccm.hpp"
#include "aes_xts.hpp"
#include "aes_kat.hpp"
#include "bench.hpp"
#include "cli.hpp"
#include "crypto_utils.hpp"
#include "encoding.hpp"
#include "file_utils.hpp"
#include "metadata.hpp"

#include <cryptlib.h>

#include <exception>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>

static bool is_gcm_mode(const std::string& mode) {
    return mode == "gcm";
}

static bool is_ccm_mode(const std::string& mode) {
    return mode == "ccm";
}

static bool is_xts_mode(const std::string& mode) {
    return mode == "xts";
}

static void print_encoded_output(const std::string& label, const Bytes& data, const std::map<std::string, std::string>& opts) {
    const std::string encode = opts.count("encode") ? opts.at("encode") : "hex";

    if (encode == "hex") {
        std::cout << label << "(hex): " << hex_encode(data) << "\n";
    } else if (encode == "base64") {
        std::cout << label << "(base64): " << base64_encode(data) << "\n";
    } else if (encode == "raw") {
        std::cout << "Raw output written to file only.\n";
    } else {
        throw std::runtime_error("Unsupported --encode value. Use hex, base64, or raw.");
    }
}

static void command_keygen(const std::map<std::string, std::string>& opts) {
    const std::string bits_s = require_option(opts, "bits");
    const std::string out_path = require_option(opts, "out");

    int bits = 0;

    try {
        bits = std::stoi(bits_s);
    } catch (...) {
        throw std::runtime_error("Invalid --bits value.");
    }

    if (bits != 128 && bits != 192 && bits != 256 && bits != 512) {
        throw std::runtime_error("Invalid key size. Expected 128, 192, 256, or 512 bits.");
    }

    Bytes key = random_bytes(static_cast<size_t>(bits / 8));
    write_file_binary(out_path, key);

    if (bits == 512) {
        std::cout << "Generated 512-bit XTS key material: " << out_path << "\n";
    } else {
        std::cout << "Generated AES-" << bits << " key: " << out_path << "\n";
    }
    print_encoded_output("Key", key, opts);
}

static void command_encrypt_gcm(const std::map<std::string, std::string>& opts, const Bytes& key) {
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : out_path + ".meta.json";

    Bytes nonce = load_or_generate_gcm_nonce(opts);
    Bytes aad = load_aad(opts);
    Bytes plaintext = load_input_data(opts);

    const std::string registry_path = opts.count("nonce-registry")
    ? opts.at("nonce-registry")
    : default_nonce_registry_path();

    check_and_record_nonce_use("gcm", key, nonce, registry_path);

    Bytes ciphertext;
    Bytes tag;

    aes_gcm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    write_file_binary(out_path, ciphertext);
    write_gcm_metadata(meta_path, out_path, key, nonce, tag, aad);

    std::cout << "AES-GCM encryption OK\n";
    std::cout << "Ciphertext file: " << out_path << "\n";
    std::cout << "Metadata file:   " << meta_path << "\n";
    std::cout << "Nonce(hex):      " << hex_encode(nonce) << "\n";
    std::cout << "Tag(hex):        " << hex_encode(tag) << "\n";

    print_encoded_output("Ciphertext", ciphertext, opts);
}

static void command_encrypt_ccm(const std::map<std::string, std::string>& opts, const Bytes& key) {
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : out_path + ".meta.json";

    Bytes nonce = load_or_generate_ccm_nonce(opts);
    Bytes aad = load_aad(opts);
    Bytes plaintext = load_input_data(opts);

    const std::string registry_path = opts.count("nonce-registry")
        ? opts.at("nonce-registry")
        : default_nonce_registry_path();

    check_and_record_nonce_use("ccm", key, nonce, registry_path);

    Bytes ciphertext;
    Bytes tag;

    aes_ccm_encrypt(key, nonce, aad, plaintext, ciphertext, tag);

    write_file_binary(out_path, ciphertext);
    write_ccm_metadata(meta_path, out_path, key, nonce, tag, aad);

    std::cout << "AES-CCM encryption OK\n";
    std::cout << "Ciphertext file: " << out_path << "\n";
    std::cout << "Metadata file:   " << meta_path << "\n";
    std::cout << "Nonce(hex):      " << hex_encode(nonce) << "\n";
    std::cout << "Tag(hex):        " << hex_encode(tag) << "\n";

    print_encoded_output("Ciphertext", ciphertext, opts);
}

static void command_encrypt_xts(const std::map<std::string, std::string>& opts) {
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : out_path + ".meta.json";

    Bytes key = load_xts_key(opts);
    Bytes tweak = load_or_generate_aes_iv(opts);
    Bytes plaintext = load_input_data(opts);

    Bytes ciphertext = aes_xts_encrypt(key, tweak, plaintext);

    write_file_binary(out_path, ciphertext);
    write_xts_metadata(meta_path, out_path, key, tweak);

    std::cout << "AES-XTS encryption OK\n";
    std::cout << "Ciphertext file: " << out_path << "\n";
    std::cout << "Metadata file:   " << meta_path << "\n";
    std::cout << "Tweak(hex):      " << hex_encode(tweak) << "\n";

    print_encoded_output("Ciphertext", ciphertext, opts);
}

static void command_encrypt_classic(
    const std::string& mode,
    const std::map<std::string, std::string>& opts,
    const Bytes& key
) {
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : out_path + ".meta.json";

    Bytes plaintext = load_input_data(opts);
    Bytes iv;

    if (mode != "ecb") {
        iv = load_or_generate_aes_iv(opts);
    }

    if (mode == "ctr") {
        const std::string registry_path = opts.count("nonce-registry")
            ? opts.at("nonce-registry")
            : default_nonce_registry_path();

        check_and_record_nonce_use("ctr", key, iv, registry_path);
    }

    const bool allow_ecb = opts.count("allow-ecb") > 0;

    Bytes ciphertext = aes_encrypt_classic(mode, key, iv, plaintext, allow_ecb);

    write_file_binary(out_path, ciphertext);
    write_classic_metadata(meta_path, out_path, mode, key, iv);

    std::cout << "AES-" << mode << " encryption OK\n";
    std::cout << "Ciphertext file: " << out_path << "\n";
    std::cout << "Metadata file:   " << meta_path << "\n";

    if (mode != "ecb") {
        std::cout << "IV(hex):         " << hex_encode(iv) << "\n";
    }

    print_encoded_output("Ciphertext", ciphertext, opts);
}

static void command_encrypt(const std::map<std::string, std::string>& opts) {
    const std::string mode = require_option(opts, "mode");

    if (is_xts_mode(mode)) {
        command_encrypt_xts(opts);
        return;
    }

    Bytes key = load_key(opts);

    if (is_gcm_mode(mode)) {
        command_encrypt_gcm(opts, key);
        return;
    }

    if (is_ccm_mode(mode)) {
        command_encrypt_ccm(opts, key);
        return;
    }

    if (is_classic_aes_mode(mode)) {
        command_encrypt_classic(mode, opts, key);
        return;
    }

    throw std::runtime_error("Unsupported mode in current milestone: " + mode);
}

static void command_decrypt_gcm(const std::map<std::string, std::string>& opts, const Bytes& key) {
    const std::string in_path = require_option(opts, "in");
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : in_path + ".meta.json";

    Bytes aad = load_aad(opts);
    Bytes ciphertext = read_file_binary(in_path);

    const std::string meta_text = read_text_file(meta_path);
    GcmMetadata meta = GcmMetadata::from_json(meta_text);

    Bytes recovered = aes_gcm_decrypt(
        key,
        meta.nonce(),
        aad,
        ciphertext,
        meta.tag()
    );

    write_file_binary(out_path, recovered);

    std::cout << "AES-GCM decryption OK\n";
    std::cout << "Plaintext file: " << out_path << "\n";
}

static void command_decrypt_ccm(const std::map<std::string, std::string>& opts, const Bytes& key) {
    const std::string in_path = require_option(opts, "in");
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : in_path + ".meta.json";

    Bytes aad = load_aad(opts);
    Bytes ciphertext = read_file_binary(in_path);

    const std::string meta_text = read_text_file(meta_path);
    CcmMetadata meta = CcmMetadata::from_json(meta_text);

    Bytes recovered = aes_ccm_decrypt(
        key,
        meta.nonce(),
        aad,
        ciphertext,
        meta.tag()
    );

    write_file_binary(out_path, recovered);

    std::cout << "AES-CCM decryption OK\n";
    std::cout << "Plaintext file: " << out_path << "\n";
}

static void command_decrypt_xts(const std::map<std::string, std::string>& opts) {
    const std::string in_path = require_option(opts, "in");
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : in_path + ".meta.json";

    Bytes key = load_xts_key(opts);
    Bytes ciphertext = read_file_binary(in_path);

    const std::string meta_text = read_text_file(meta_path);
    XtsMetadata meta = XtsMetadata::from_json(meta_text);

    Bytes recovered = aes_xts_decrypt(
        key,
        meta.tweak(),
        ciphertext
    );

    write_file_binary(out_path, recovered);

    std::cout << "AES-XTS decryption OK\n";
    std::cout << "Plaintext file: " << out_path << "\n";
}

static void command_decrypt_classic(
    const std::string& mode,
    const std::map<std::string, std::string>& opts,
    const Bytes& key
) {
    const std::string in_path = require_option(opts, "in");
    const std::string out_path = require_option(opts, "out");
    const std::string meta_path = opts.count("meta") ? opts.at("meta") : in_path + ".meta.json";

    Bytes ciphertext = read_file_binary(in_path);

    const std::string meta_text = read_text_file(meta_path);
    ClassicMetadata meta = ClassicMetadata::from_json(meta_text);

    if (meta.mode() != mode) {
        throw std::runtime_error("Metadata mode mismatch. CLI mode is " + mode + ", metadata mode is " + meta.mode() + ".");
    }

    Bytes recovered = aes_decrypt_classic(mode, key, meta.iv(), ciphertext);

    write_file_binary(out_path, recovered);

    std::cout << "AES-" << mode << " decryption OK\n";
    std::cout << "Plaintext file: " << out_path << "\n";
}

static void command_decrypt(const std::map<std::string, std::string>& opts) {
    const std::string mode = require_option(opts, "mode");

    if (is_xts_mode(mode)) {
        command_decrypt_xts(opts);
        return;
    }

    Bytes key = load_key(opts);

    if (is_gcm_mode(mode)) {
        command_decrypt_gcm(opts, key);
        return;
    }

    if (is_ccm_mode(mode)) {
        command_decrypt_ccm(opts, key);
        return;
    }

    if (is_classic_aes_mode(mode)) {
        command_decrypt_classic(mode, opts, key);
        return;
    }

    throw std::runtime_error("Unsupported mode in current milestone: " + mode);
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            print_usage();
            return 1;
        }

        const std::string command = argv[1];

        if (command == "--help" || command == "-h" || command == "help") {
            print_usage();
            return 0;
        }

        if (command == "--kat") {
            if (argc < 3) {
                throw std::runtime_error("Missing KAT file path after --kat.");
            }

            std::map<std::string, std::string> kat_opts;
            kat_opts["kat"] = argv[2];

            command_kat(kat_opts);
            return 0;
        }

        const auto opts = parse_options(argc, argv, 2);

        if (command == "keygen") {
            command_keygen(opts);
        } else if (command == "encrypt") {
            command_encrypt(opts);
        } else if (command == "decrypt") {
            command_decrypt(opts);
        } else if (command == "kat") {
            command_kat(opts);
        } else if (command == "bench") {
            command_bench(opts);
        } else {
            throw std::runtime_error("Unknown command: " + command);
        }

        return 0;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ error: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}