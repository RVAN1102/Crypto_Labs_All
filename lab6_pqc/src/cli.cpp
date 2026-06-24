#include "pqtool/cli.hpp"

#include "pqtool/bench.hpp"
#include "pqtool/errors.hpp"
#include "pqtool/file_io.hpp"
#include "pqtool/mldsa.hpp"
#include "pqtool/mlkem.hpp"
#include "pqtool/openssl_utils.hpp"
#include "pqtool/pq_cert.hpp"
#include "pqtool/pq_key.hpp"

#include <openssl/crypto.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>

namespace pqtool {
namespace {

using Options = std::map<std::string, std::string>;

Options parse_options(int argc, char** argv, int start) {
    Options options;
    for (int i = start; i < argc; ++i) {
        const std::string token = argv[i];
        if (token.rfind("--", 0) != 0 || token.size() == 2) {
            fail("Unexpected argument: " + token);
        }
        const std::string key = token.substr(2);
        if (options.count(key) != 0) {
            fail("Duplicate option: --" + key);
        }
        std::string value = "true";
        if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
            value = argv[++i];
        }
        options.emplace(key, value);
    }
    return options;
}

std::string require(const Options& options, const std::string& name) {
    const auto found = options.find(name);
    if (found == options.end() || found->second == "true") {
        fail("Missing required option: --" + name);
    }
    return found->second;
}

std::string optional(const Options& options, const std::string& name, const std::string& fallback) {
    const auto found = options.find(name);
    return found == options.end() ? fallback : found->second;
}

int positive_integer(const std::string& value, const std::string& name) {
    try {
        const int parsed = std::stoi(value);
        if (parsed <= 0) throw std::invalid_argument("range");
        return parsed;
    } catch (...) {
        fail("Invalid positive integer for --" + name + ".");
    }
}

std::vector<std::string> split(const std::string& value, char separator) {
    std::vector<std::string> result;
    std::istringstream input(value);
    std::string item;
    while (std::getline(input, item, separator)) {
        if (item.empty()) fail("Malformed list option.");
        result.push_back(item);
    }
    return result;
}

std::vector<std::size_t> sizes(const std::string& value) {
    std::vector<std::size_t> result;
    for (const auto& item : split(value, ',')) {
        try {
            const auto parsed = std::stoull(item);
            if (parsed == 0) throw std::invalid_argument("range");
            result.push_back(static_cast<std::size_t>(parsed));
        } catch (...) {
            fail("Invalid benchmark message size.");
        }
    }
    return result;
}

void print_help() {
    std::cout <<
        "pqtool - OpenSSL-only post-quantum signature and KEM tool\n"
        "Usage: pqtool <command> [options]\n"
        "Commands:\n"
        "  version | selftest\n"
        "  keygen --algo NAME --pub FILE --priv FILE\n"
        "  sign --algo NAME --priv FILE --in FILE --out FILE\n"
        "  verify --algo NAME --pub FILE --in FILE --sig FILE\n"
        "  batch-verify --algo NAME --pub FILE --manifest FILE\n"
        "  encaps --algo NAME --pub FILE --ct FILE --ss FILE\n"
        "  decaps --algo NAME --priv FILE --ct FILE --ss FILE\n"
        "  batch-decaps --algo NAME --priv FILE --manifest FILE\n"
        "  cert-create --subject TEXT --subject-pub FILE --issuer TEXT --ca-priv FILE --out FILE\n"
        "  cert-verify --cert FILE --ca-pub FILE\n"
        "  bench --algo NAME --ops LIST [--sizes LIST] --runs N --out FILE\n"
        "  timing-variance --algo NAME --case NAME --runs N --out FILE\n";
}

std::string algorithm_option(const Options& options) {
    return normalize_algorithm(require(options, "algo"));
}

void command_keygen(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    PkeyPtr key = generate_key(algorithm);
    save_private_key(require(options, "priv"), key.get());
    save_public_key(require(options, "pub"), key.get());
    std::cout << "Generated " << algorithm << " key pair.\n";
}

void command_sign(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    if (!is_mldsa(algorithm)) fail("Signing requires ML-DSA.");
    PkeyPtr key = load_private_key(require(options, "priv"), algorithm);
    write_binary_atomic(require(options, "out"), mldsa_sign(key.get(), read_binary(require(options, "in"))));
    std::cout << "Signature written.\n";
}

int command_verify(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    if (!is_mldsa(algorithm)) fail("Verification requires ML-DSA.");
    PkeyPtr key = load_public_key(require(options, "pub"), algorithm);
    const bool valid = mldsa_verify(
        key.get(), read_binary(require(options, "in")), read_binary(require(options, "sig")));
    std::cout << (valid ? "VALID\n" : "INVALID\n");
    return valid ? 0 : 3;
}

int command_batch_verify(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    if (!is_mldsa(algorithm)) fail("Batch verification requires ML-DSA.");
    PkeyPtr key = load_public_key(require(options, "pub"), algorithm);
    std::istringstream manifest(read_text(require(options, "manifest")));
    std::string line;
    int total = 0;
    int valid = 0;
    while (std::getline(manifest, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto fields = split(line, '|');
        if (fields.size() != 2) fail("Malformed batch verification manifest.");
        ++total;
        if (mldsa_verify(key.get(), read_binary(fields[0]), read_binary(fields[1]))) ++valid;
    }
    if (total == 0) fail("Batch verification manifest is empty.");
    std::cout << "Batch verification: " << valid << "/" << total << " valid.\n";
    return valid == total ? 0 : 3;
}

void command_encaps(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    if (!is_mlkem(algorithm)) fail("Encapsulation requires ML-KEM.");
    PkeyPtr key = load_public_key(require(options, "pub"), algorithm);
    Encapsulation result = mlkem_encapsulate(key.get());
    write_binary_atomic(require(options, "ct"), result.ciphertext);
    write_binary_atomic(require(options, "ss"), result.shared_secret);
    cleanse(result.shared_secret.data(), result.shared_secret.size());
    std::cout << "Encapsulation complete; shared secret written to requested file.\n";
}

void command_decaps(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    if (!is_mlkem(algorithm)) fail("Decapsulation requires ML-KEM.");
    PkeyPtr key = load_private_key(require(options, "priv"), algorithm);
    Bytes secret = mlkem_decapsulate(key.get(), read_binary(require(options, "ct")));
    write_binary_atomic(require(options, "ss"), secret);
    cleanse(secret.data(), secret.size());
    std::cout << "Decapsulation complete; shared secret written to requested file.\n";
}

int command_batch_decaps(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    if (!is_mlkem(algorithm)) fail("Batch decapsulation requires ML-KEM.");
    PkeyPtr key = load_private_key(require(options, "priv"), algorithm);
    std::istringstream manifest(read_text(require(options, "manifest")));
    std::string line;
    int total = 0;
    double total_ms = 0.0;
    while (std::getline(manifest, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto start = std::chrono::steady_clock::now();
        Bytes secret = mlkem_decapsulate(key.get(), read_binary(line));
        total_ms += std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();
        cleanse(secret.data(), secret.size());
        ++total;
    }
    if (total == 0) fail("Batch decapsulation manifest is empty.");
    std::cout << "Batch decapsulation: " << total << " items, mean "
              << (total_ms / total) << " ms.\n";
    return 0;
}

void command_cert_create(const Options& options) {
    const std::string algorithm = normalize_algorithm(optional(options, "algo", "mldsa-44"));
    if (!is_mldsa(algorithm)) fail("Certificate signing requires ML-DSA.");
    PkeyPtr subject = load_public_key(require(options, "subject-pub"), algorithm);
    PkeyPtr ca = load_private_key(require(options, "ca-priv"), algorithm);
    const PqCertificate certificate = create_certificate(
        require(options, "subject"), require(options, "issuer"),
        subject.get(), algorithm, ca.get(), algorithm);
    write_text_atomic(require(options, "out"), serialize_certificate(certificate));
    std::cout << "Educational PQ certificate written.\n";
}

int command_cert_verify(const Options& options) {
    const PqCertificate certificate = parse_certificate(read_text(require(options, "cert")));
    PkeyPtr ca = load_public_key(require(options, "ca-pub"), certificate.signature_algorithm);
    const bool valid = verify_certificate(certificate, ca.get());
    std::cout << (valid ? "CERTIFICATE VALID\n" : "CERTIFICATE INVALID\n");
    return valid ? 0 : 3;
}

void command_bench(const Options& options) {
    const std::string algorithm = algorithm_option(options);
    run_benchmark(
        algorithm,
        split(require(options, "ops"), ','),
        sizes(optional(options, "sizes", "1024")),
        positive_integer(require(options, "runs"), "runs"),
        require(options, "out"));
    std::cout << "Benchmark CSV written.\n";
}

void command_timing(const Options& options) {
    run_timing_variance(
        algorithm_option(options),
        require(options, "case"),
        positive_integer(require(options, "runs"), "runs"),
        require(options, "out"));
    std::cout << "Timing variance CSV written.\n";
}

void command_selftest() {
    const Bytes message{'p', 'q', 't', 'o', 'o', 'l'};
    PkeyPtr dsa = generate_key("ML-DSA-44");
    const Bytes signature = mldsa_sign(dsa.get(), message);
    if (!mldsa_verify(dsa.get(), message, signature)) fail("ML-DSA self-test failed.");
    PkeyPtr kem = generate_key("ML-KEM-512");
    Encapsulation encapsulation = mlkem_encapsulate(kem.get());
    Bytes secret = mlkem_decapsulate(kem.get(), encapsulation.ciphertext);
    const bool matches =
        secret.size() == encapsulation.shared_secret.size() &&
        CRYPTO_memcmp(secret.data(), encapsulation.shared_secret.data(), secret.size()) == 0;
    cleanse(secret.data(), secret.size());
    cleanse(encapsulation.shared_secret.data(), encapsulation.shared_secret.size());
    if (!matches) fail("ML-KEM self-test failed.");
    std::cout << "Self-test passed.\n";
}

} // namespace

int run_cli(int argc, char** argv) {
    if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "help") {
        print_help();
        return 0;
    }
    const std::string command = argv[1];
    if (command == "version") {
        std::cout << "pqtool 1.0\n" << openssl_version_string() << '\n';
        return 0;
    }
    if (command == "selftest") {
        command_selftest();
        return 0;
    }
    const Options options = parse_options(argc, argv, 2);
    if (command == "keygen") command_keygen(options);
    else if (command == "sign") command_sign(options);
    else if (command == "verify") return command_verify(options);
    else if (command == "batch-verify") return command_batch_verify(options);
    else if (command == "encaps") command_encaps(options);
    else if (command == "decaps") command_decaps(options);
    else if (command == "batch-decaps") return command_batch_decaps(options);
    else if (command == "cert-create") command_cert_create(options);
    else if (command == "cert-verify") return command_cert_verify(options);
    else if (command == "bench") command_bench(options);
    else if (command == "timing-variance") command_timing(options);
    else fail("Unknown command: " + command);
    return 0;
}

} // namespace pqtool
