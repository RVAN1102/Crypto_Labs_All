#include "cli.hpp"

#include "bench.hpp"
#include "envelope.hpp"
#include "file_utils.hpp"
#include "kat.hpp"
#include "rsa_oaep.hpp"

#include <iostream>
#include <stdexcept>

static bool starts_with_dash(const std::string& s) {
    return s.rfind("--", 0) == 0;
}

static std::string key_path(
    const std::map<std::string, std::string>& opts,
    const std::string& a,
    const std::string& b
) {
    auto it = opts.find(a);
    if (it != opts.end()) {
        return it->second;
    }
    return require_option(opts, b);
}

static int parse_int(const std::string& value, const std::string& name) {
    try {
        return std::stoi(value);
    } catch (...) {
        throw std::runtime_error("Invalid integer for --" + name + ".");
    }
}

std::map<std::string, std::string> parse_options(int argc, char* argv[], int start_index) {
    std::map<std::string, std::string> opts;

    for (int i = start_index; i < argc; ++i) {
        const std::string token = argv[i];
        if (!starts_with_dash(token)) {
            throw std::runtime_error("Unexpected positional argument: " + token);
        }

        const std::string key = token.substr(2);
        std::string value = "true";

        if ((i + 1) < argc && !starts_with_dash(argv[i + 1])) {
            value = argv[++i];
        }

        opts[key] = value;
    }

    return opts;
}

std::string require_option(const std::map<std::string, std::string>& opts, const std::string& name) {
    const auto it = opts.find(name);
    if (it == opts.end() || it->second.empty()) {
        throw std::runtime_error("Missing required option: --" + name);
    }
    return it->second;
}

std::string get_option_or(const std::map<std::string, std::string>& opts, const std::string& name, const std::string& fallback) {
    const auto it = opts.find(name);
    return it == opts.end() ? fallback : it->second;
}

Bytes load_label(const std::map<std::string, std::string>& opts) {
    if (opts.count("label-text")) {
        const std::string label = opts.at("label-text");
        return Bytes(label.begin(), label.end());
    }

    if (opts.count("label")) {
        return read_file_binary(opts.at("label"));
    }

    if (opts.count("label-hex")) {
        return hex_decode(opts.at("label-hex"));
    }

    return {};
}

Bytes load_input_data(const std::map<std::string, std::string>& opts) {
    if (opts.count("text")) {
        const std::string text = opts.at("text");
        return Bytes(text.begin(), text.end());
    }

    if (opts.count("in")) {
        return read_file_binary(opts.at("in"));
    }

    throw std::runtime_error("Missing input. Use --in FILE or --text TEXT.");
}

static void command_keygen(const std::map<std::string, std::string>& opts) {
    const int bits = parse_int(require_option(opts, "bits"), "bits");
    const std::string private_path = key_path(opts, "private", "priv");
    const std::string public_path = key_path(opts, "public", "pub");

    generate_rsa_keypair_der_files(bits, private_path, public_path);
    std::cout << "Generated RSA-" << bits << " DER key pair\n";
    std::cout << "Private key: " << private_path << "\n";
    std::cout << "Public key:  " << public_path << "\n";
}

static void command_oaep_encrypt(const std::map<std::string, std::string>& opts) {
    const std::string public_path = key_path(opts, "public", "pub");
    const std::string out_path = require_option(opts, "out");

    const Bytes public_key = read_file_binary(public_path);
    const Bytes plaintext = load_input_data(opts);
    const Bytes label = load_label(opts);
    const Bytes ciphertext = rsa_oaep_sha256_encrypt_der(public_key, plaintext, label);

    write_file_binary(out_path, ciphertext);
    std::cout << "RSA-OAEP(SHA-256) encryption OK\n";
    std::cout << "RSA bits: " << rsa_public_key_bits_der(public_key) << "\n";
    std::cout << "Plaintext bytes: " << plaintext.size() << "\n";
    std::cout << "Ciphertext file: " << out_path << "\n";
}

static void command_oaep_decrypt(const std::map<std::string, std::string>& opts) {
    const std::string private_path = key_path(opts, "private", "priv");
    const std::string in_path = require_option(opts, "in");
    const std::string out_path = require_option(opts, "out");

    const Bytes private_key = read_file_binary(private_path);
    const Bytes ciphertext = read_file_binary(in_path);
    const Bytes label = load_label(opts);
    const Bytes plaintext = rsa_oaep_sha256_decrypt_der(private_key, ciphertext, label);

    write_file_binary(out_path, plaintext);
    std::cout << "RSA-OAEP(SHA-256) decryption OK\n";
    std::cout << "Plaintext file: " << out_path << "\n";
}

static void command_hybrid_encrypt(const std::map<std::string, std::string>& opts) {
    const std::string public_path = key_path(opts, "public", "pub");
    const std::string out_path = require_option(opts, "out");
    const std::string envelope_path = get_option_or(opts, "envelope", out_path + ".envelope.json");

    const Bytes public_key = read_file_binary(public_path);
    const Bytes plaintext = load_input_data(opts);
    const Bytes label = load_label(opts);
    const HybridEncryptResult result = hybrid_encrypt(public_key, plaintext, label, out_path);

    write_file_binary(out_path, result.ciphertext);
    write_text_file(envelope_path, result.envelope.to_json());

    std::cout << "Hybrid encryption OK\n";
    std::cout << "Ciphertext file: " << out_path << "\n";
    std::cout << "Envelope file:   " << envelope_path << "\n";
    std::cout << "RSA bits:        " << result.envelope.rsa_bits << "\n";
}

static void command_hybrid_decrypt(const std::map<std::string, std::string>& opts) {
    const std::string private_path = key_path(opts, "private", "priv");
    const std::string in_path = require_option(opts, "in");
    const std::string envelope_path = require_option(opts, "envelope");
    const std::string out_path = require_option(opts, "out");

    const Bytes private_key = read_file_binary(private_path);
    const Bytes ciphertext = read_file_binary(in_path);
    const HybridEnvelope envelope = HybridEnvelope::from_json(read_text_file(envelope_path));
    const Bytes label = load_label(opts);
    const Bytes plaintext = hybrid_decrypt(private_key, ciphertext, envelope, label);

    write_file_binary(out_path, plaintext);
    std::cout << "Hybrid decryption OK\n";
    std::cout << "Plaintext file: " << out_path << "\n";
}

void print_usage() {
    std::cout
        << "rsatool - Lab 3 RSA-OAEP(SHA-256) and hybrid encryption tool\n\n"
        << "Commands:\n"
        << "  keygen         --bits 3072|4096 --private private.der --public public.der\n"
        << "  oaep-encrypt   --pub public.der --in msg.bin --out msg.rsa [--label-text TEXT]\n"
        << "  oaep-decrypt   --priv private.der --in msg.rsa --out msg.bin [--label-text TEXT]\n"
        << "  seal           --pub public.der --in plain.bin --out cipher.bin [--envelope env.json] [--label-text TEXT]\n"
        << "  open           --priv private.der --in cipher.bin --envelope env.json --out plain.bin [--label-text TEXT]\n"
        << "  hybrid-encrypt Alias for seal\n"
        << "  hybrid-decrypt Alias for open\n"
        << "  kat            --kat vectors/rsa_hybrid_kat.json\n"
        << "  bench          --out raw.csv --summary summary.csv [--runs N] [--ops N]\n\n"
        << "Options:\n"
        << "  --private FILE, --priv FILE      RSA private key in DER format\n"
        << "  --public FILE, --pub FILE        RSA public key in DER format\n"
        << "  --in FILE, --text TEXT           Binary file input or UTF-8 text input\n"
        << "  --out FILE                       Binary output path\n"
        << "  --envelope FILE                  Hybrid envelope JSON path\n"
        << "  --label-text TEXT                Optional OAEP label text\n"
        << "  --label FILE                     Optional OAEP label file\n"
        << "  --label-hex HEX                  Optional OAEP label bytes in hex\n"
        << "  --sizes LIST                     Hybrid benchmark sizes, e.g. 1k,16k,1m\n"
        << "  --rsa-sizes LIST                 RSA-OAEP benchmark message sizes, e.g. 32,190,318\n"
        << "  --rsa-bits LIST                  RSA sizes to benchmark, default 3072,4096\n\n"
        << "Direct RSA-OAEP uses SHA-256 and is limited to 318 bytes for RSA-3072 and 446 bytes for RSA-4096.\n"
        << "Use seal/open or hybrid-encrypt/hybrid-decrypt for large files.\n";
}

int run_command(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const std::string command = argv[1];
    if (command == "--help" || command == "-h" || command == "help") {
        print_usage();
        return 0;
    }

    const auto opts = parse_options(argc, argv, 2);

    if (command == "keygen") {
        command_keygen(opts);
    } else if (command == "oaep-encrypt") {
        command_oaep_encrypt(opts);
    } else if (command == "oaep-decrypt") {
        command_oaep_decrypt(opts);
    } else if (command == "seal" || command == "hybrid-encrypt") {
        command_hybrid_encrypt(opts);
    } else if (command == "open" || command == "hybrid-decrypt") {
        command_hybrid_decrypt(opts);
    } else if (command == "kat") {
        command_kat(opts);
    } else if (command == "bench") {
        command_bench(opts);
    } else {
        throw std::runtime_error("Unknown command: " + command);
    }

    return 0;
}
