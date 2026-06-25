#include "sigtool/cli.hpp"

#include "sigtool/bench.hpp"
#include "sigtool/encoding.hpp"
#include "sigtool/file_utils.hpp"
#include "sigtool/signatures.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace sigtool {

namespace {

struct ParsedArgs {
    std::map<std::string, std::string> values;
};

bool starts_with_dash(const std::string& value) {
    return value.rfind("--", 0) == 0;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool ends_with_ci(const std::string& value, const std::string& suffix) {
    const auto l = lower(value);
    return l.size() >= suffix.size() && l.compare(l.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool parse_options(int argc, char** argv, int start, ParsedArgs& args, std::string& error) {
    args = ParsedArgs{};
    for (int i = start; i < argc; ++i) {
        const std::string token = argv[i];
        if (!starts_with_dash(token)) {
            error = "unexpected positional argument: " + token;
            return false;
        }
        if (i + 1 >= argc || starts_with_dash(argv[i + 1])) {
            error = "missing value for " + token;
            return false;
        }
        const std::string key = token.substr(2);
        if (args.values.find(key) != args.values.end()) {
            error = "duplicate option: " + token;
            return false;
        }
        args.values[key] = argv[++i];
    }
    return true;
}

bool require_option(const ParsedArgs& args, const std::string& name, std::string& value, std::string& error) {
    const auto it = args.values.find(name);
    if (it == args.values.end() || it->second.empty()) {
        error = "missing required option --" + name;
        return false;
    }
    value = it->second;
    return true;
}

bool reject_unsupported_options(
    const ParsedArgs& args,
    const std::set<std::string>& allowed,
    std::string& error) {

    for (const auto& entry : args.values) {
        if (allowed.find(entry.first) == allowed.end()) {
            error = "unsupported option for this command: --" + entry.first;
            return false;
        }
    }
    return true;
}

std::string option_or(const ParsedArgs& args, const std::string& name, const std::string& fallback) {
    const auto it = args.values.find(name);
    return it == args.values.end() ? fallback : it->second;
}

bool parse_algorithm_option(const ParsedArgs& args, Algorithm& algorithm, std::string& error) {
    std::string text;
    if (!require_option(args, "algo", text, error)) {
        return false;
    }
    if (!parse_algorithm(text, algorithm)) {
        error = "unsupported algorithm: " + text;
        return false;
    }
    return true;
}

bool require_sha256(const ParsedArgs& args, std::string& error) {
    std::string hash;
    if (!require_option(args, "hash", hash, error)) {
        return false;
    }
    if (!is_supported_hash_name(hash)) {
        error = "unsupported hash: " + hash + " (Lab 5 requires sha256)";
        return false;
    }
    return true;
}

bool parse_encoding_option(
    const ParsedArgs& args,
    Algorithm algorithm,
    bool verify,
    SignatureEncoding& encoding,
    std::string& error) {

    encoding = algorithm == Algorithm::EcdsaP256 ? SignatureEncoding::Der : SignatureEncoding::Raw;
    const auto it = args.values.find("encode");
    if (it == args.values.end()) {
        (void)verify;
        return true;
    }
    if (!parse_signature_encoding(it->second, encoding)) {
        error = "unsupported signature encoding: " + it->second;
        return false;
    }
    return true;
}

bool infer_pem_format(const ParsedArgs& args, const std::vector<std::string>& paths, bool& pem, std::string& error) {
    const auto it = args.values.find("format");
    if (it != args.values.end()) {
        const auto fmt = lower(it->second);
        if (fmt == "pem") {
            pem = true;
            return true;
        }
        if (fmt == "der") {
            pem = false;
            return true;
        }
        error = "unsupported key format: " + it->second;
        return false;
    }

    pem = true;
    for (const auto& path : paths) {
        if (ends_with_ci(path, ".der")) {
            pem = false;
        }
    }
    return true;
}

int fail(const std::string& error) {
    std::cerr << "error: " << error << "\n";
    return 1;
}

std::string utc_now() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc{};
#if defined(_WIN32)
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    std::ostringstream out;
    out << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

std::string key_metadata_json(Algorithm algorithm, bool pem, const std::string& pub_path, const std::string& priv_path) {
    std::string json;
    json += "{\n";
    json += "  \"creation_time\": \"" + utc_now() + "\",\n";
    json += "  \"algorithm\": \"" + algorithm_name(algorithm) + "\",\n";
    json += "  \"hash\": \"SHA-256\",\n";
    if (algorithm == Algorithm::EcdsaP256) {
        json += "  \"curve\": \"NIST P-256 / secp256r1\",\n";
        json += "  \"nonce\": \"RFC6979 deterministic HMAC-SHA256\",\n";
    } else {
        json += "  \"modulus_bits\": 3072,\n";
        json += "  \"padding\": \"RSA-PSS\",\n";
        json += "  \"mgf\": \"MGF1-SHA256\",\n";
        json += "  \"salt_length_bytes\": 32,\n";
        json += "  \"public_exponent\": 65537,\n";
    }
    json += "  \"key_format\": \"" + std::string(pem ? "PEM" : "DER") + "\",\n";
    json += "  \"private_key_file\": \"" + json_escape(priv_path) + "\",\n";
    json += "  \"public_key_file\": \"" + json_escape(pub_path) + "\"\n";
    json += "}\n";
    return json;
}

bool parse_positive_int(const std::string& text, int& out) {
    try {
        std::size_t consumed = 0;
        const long value = std::stol(text, &consumed, 10);
        if (consumed != text.size() || value <= 0 || value > 1000000) {
            return false;
        }
        out = static_cast<int>(value);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_size_token(const std::string& text, std::size_t& out) {
    const auto value = lower(text);
    if (value == "1k" || value == "1kb" || value == "1kib") {
        out = 1024ULL;
        return true;
    }
    if (value == "16k" || value == "16kb" || value == "16kib") {
        out = 16ULL * 1024ULL;
        return true;
    }
    if (value == "1m" || value == "1mb" || value == "1mib") {
        out = 1024ULL * 1024ULL;
        return true;
    }
    if (value == "8m" || value == "8mb" || value == "8mib") {
        out = 8ULL * 1024ULL * 1024ULL;
        return true;
    }
    return false;
}

std::vector<std::string> split_csv(const std::string& text) {
    std::vector<std::string> out;
    std::stringstream ss(text);
    std::string item;
    while (std::getline(ss, item, ',')) {
        out.push_back(item);
    }
    return out;
}

std::string trim_ascii_ws(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    std::size_t first = 0;
    while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) {
        ++first;
    }
    return first == 0 ? value : value.substr(first);
}

int command_keygen(const ParsedArgs& args) {
    std::string error;
    if (!reject_unsupported_options(args, {"algo", "pub", "priv", "format", "meta"}, error)) {
        return fail(error);
    }

    Algorithm algorithm;
    if (!parse_algorithm_option(args, algorithm, error)) {
        return fail(error);
    }

    std::string pub_path;
    std::string priv_path;
    if (!require_option(args, "pub", pub_path, error) || !require_option(args, "priv", priv_path, error)) {
        return fail(error);
    }

    bool pem = true;
    if (!infer_pem_format(args, {pub_path, priv_path}, pem, error)) {
        return fail(error);
    }

    KeyPair pair;
    if (!generate_key_pair(algorithm, pem, pair, error)) {
        return fail(error);
    }
    if (!write_binary_file(priv_path, pair.private_key, error) || !write_binary_file(pub_path, pair.public_key, error)) {
        return fail(error);
    }
    const auto meta_it = args.values.find("meta");
    if (meta_it != args.values.end() &&
        !write_text_file(meta_it->second, key_metadata_json(algorithm, pem, pub_path, priv_path), error)) {
        return fail(error);
    }

    std::cout << "Generated " << algorithm_name(algorithm) << " key pair\n";
    std::cout << "Private key: " << priv_path << "\n";
    std::cout << "Public key:  " << pub_path << "\n";
    std::cout << "Format:      " << (pem ? "PEM" : "DER") << "\n";
    return 0;
}

int command_sign(const ParsedArgs& args) {
    std::string error;
    if (!reject_unsupported_options(args, {"algo", "priv", "in", "out", "hash", "encode"}, error)) {
        return fail(error);
    }

    Algorithm algorithm;
    if (!parse_algorithm_option(args, algorithm, error) || !require_sha256(args, error)) {
        return fail(error);
    }

    std::string priv_path;
    std::string in_path;
    std::string out_path;
    if (!require_option(args, "priv", priv_path, error) ||
        !require_option(args, "in", in_path, error) ||
        !require_option(args, "out", out_path, error)) {
        return fail(error);
    }

    SignatureEncoding encoding;
    if (!parse_encoding_option(args, algorithm, false, encoding, error)) {
        return fail(error);
    }

    Bytes private_key;
    Bytes message;
    Bytes signature;
    if (!read_binary_file(priv_path, private_key, error) ||
        !read_binary_file(in_path, message, error) ||
        !sign_message(algorithm, private_key, message, encoding, signature, error) ||
        !write_binary_file(out_path, signature, error)) {
        return fail(error);
    }

    std::cout << "Signature created\n";
    std::cout << "Algorithm: " << algorithm_name(algorithm) << "\n";
    std::cout << "Hash:      sha256\n";
    std::cout << "Encoding:  " << signature_encoding_name(encoding) << "\n";
    std::cout << "Output:    " << out_path << "\n";
    return 0;
}

int command_verify(const ParsedArgs& args, bool quiet) {
    std::string error;
    if (!reject_unsupported_options(args, {"algo", "pub", "in", "sig", "hash", "encode"}, error)) {
        return fail(error);
    }

    Algorithm algorithm;
    if (!parse_algorithm_option(args, algorithm, error) || !require_sha256(args, error)) {
        return fail(error);
    }

    std::string pub_path;
    std::string in_path;
    std::string sig_path;
    if (!require_option(args, "pub", pub_path, error) ||
        !require_option(args, "in", in_path, error) ||
        !require_option(args, "sig", sig_path, error)) {
        return fail(error);
    }

    SignatureEncoding encoding;
    if (!parse_encoding_option(args, algorithm, true, encoding, error)) {
        return fail(error);
    }

    Bytes public_key;
    Bytes message;
    Bytes signature;
    VerifyResult result;
    if (!read_binary_file(pub_path, public_key, error) ||
        !read_binary_file(in_path, message, error) ||
        !read_binary_file(sig_path, signature, error) ||
        !verify_message(algorithm, public_key, message, signature, encoding, result, error)) {
        return fail(error);
    }

    if (result.ok) {
        if (!quiet) {
            std::cout << "[PASS] signature verified\n";
        }
        return 0;
    }
    if (!quiet) {
        std::cout << "[FAIL] signature verification failed\n";
    }
    return 1;
}

int command_batch_verify(const ParsedArgs& args) {
    std::string error;
    if (!reject_unsupported_options(args, {"algo", "pub", "manifest", "hash", "encode"}, error)) {
        return fail(error);
    }

    Algorithm algorithm;
    if (!parse_algorithm_option(args, algorithm, error) || !require_sha256(args, error)) {
        return fail(error);
    }

    std::string pub_path;
    std::string manifest_path;
    if (!require_option(args, "pub", pub_path, error) || !require_option(args, "manifest", manifest_path, error)) {
        return fail(error);
    }

    SignatureEncoding encoding;
    if (!parse_encoding_option(args, algorithm, true, encoding, error)) {
        return fail(error);
    }

    Bytes public_key;
    std::string manifest;
    if (!read_binary_file(pub_path, public_key, error) || !read_text_file(manifest_path, manifest, error)) {
        return fail(error);
    }

    int total = 0;
    int passed = 0;
    std::stringstream ss(manifest);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const auto comma = line.find(',');
        if (comma == std::string::npos || comma == 0 || comma == line.size() - 1) {
            return fail("malformed manifest line: " + line);
        }
        const std::string msg_path = trim_ascii_ws(line.substr(0, comma));
        const std::string sig_path = trim_ascii_ws(line.substr(comma + 1));
        Bytes message;
        Bytes signature;
        VerifyResult result;
        if (!read_binary_file(msg_path, message, error) ||
            !read_binary_file(sig_path, signature, error) ||
            !verify_message(algorithm, public_key, message, signature, encoding, result, error)) {
            return fail(error);
        }
        ++total;
        if (result.ok) {
            ++passed;
        }
    }

    std::cout << "Batch verify: total=" << total << " pass=" << passed << " fail=" << (total - passed) << "\n";
    return total > 0 && total == passed ? 0 : 1;
}

int command_bench(const ParsedArgs& args) {
    std::string error;
    if (!reject_unsupported_options(
            args,
            {"out", "summary", "platform", "runs", "ops", "algos", "sizes"},
            error)) {
        return fail(error);
    }

    BenchConfig config;
    config.out_path = option_or(args, "out", "artifacts/windows/bench/bench_windows_raw.csv");
    config.summary_path = option_or(args, "summary", "artifacts/windows/bench/bench_windows_summary.csv");
    config.platform = option_or(args, "platform", "local");

    if (!parse_positive_int(option_or(args, "runs", "30"), config.runs) ||
        !parse_positive_int(option_or(args, "ops", "1"), config.ops)) {
        return fail("invalid --runs or --ops");
    }

    const std::string algos = option_or(args, "algos", "ecdsa-p256,rsa-pss-3072");
    for (const auto& token : split_csv(algos)) {
        Algorithm algorithm;
        if (token.empty() || !parse_algorithm(token, algorithm)) {
            return fail("unsupported benchmark algorithm: " + token);
        }
        config.algorithms.push_back(algorithm);
    }

    const std::string sizes = option_or(args, "sizes", "1k,16k,1m,8m");
    for (const auto& token : split_csv(sizes)) {
        std::size_t size = 0;
        if (token.empty() || !parse_size_token(token, size)) {
            return fail("unsupported benchmark size: " + token);
        }
        config.sizes.push_back(size);
    }

    std::string output;
    if (!run_benchmark(config, output, error)) {
        return fail(error);
    }
    std::cout << output;
    return 0;
}

int command_kat(const ParsedArgs& args) {
    std::string error;
    if (!reject_unsupported_options(args, {}, error)) {
        return fail(error);
    }

    const Bytes message = {'L', 'a', 'b', '5', '-', 'K', 'A', 'T', 0x00, 0x01};

    KeyPair ecdsa;
    Bytes ecdsa_sig1;
    Bytes ecdsa_sig2;
    VerifyResult result;
    if (!generate_key_pair(Algorithm::EcdsaP256, true, ecdsa, error) ||
        !sign_message(Algorithm::EcdsaP256, ecdsa.private_key, message, SignatureEncoding::Der, ecdsa_sig1, error) ||
        !sign_message(Algorithm::EcdsaP256, ecdsa.private_key, message, SignatureEncoding::Der, ecdsa_sig2, error) ||
        ecdsa_sig1 != ecdsa_sig2 ||
        !verify_message(Algorithm::EcdsaP256, ecdsa.public_key, message, ecdsa_sig1, SignatureEncoding::Der, result, error) ||
        !result.ok) {
        return fail(error.empty() ? "ECDSA-P256 deterministic KAT failed" : error);
    }

    KeyPair rsa;
    Bytes rsa_sig1;
    Bytes rsa_sig2;
    if (!generate_key_pair(Algorithm::RsaPss3072, true, rsa, error) ||
        !sign_message(Algorithm::RsaPss3072, rsa.private_key, message, SignatureEncoding::Raw, rsa_sig1, error) ||
        !sign_message(Algorithm::RsaPss3072, rsa.private_key, message, SignatureEncoding::Raw, rsa_sig2, error) ||
        rsa_sig1 == rsa_sig2 ||
        !verify_message(Algorithm::RsaPss3072, rsa.public_key, message, rsa_sig1, SignatureEncoding::Raw, result, error) ||
        !result.ok ||
        !verify_message(Algorithm::RsaPss3072, rsa.public_key, message, rsa_sig2, SignatureEncoding::Raw, result, error) ||
        !result.ok) {
        return fail(error.empty() ? "RSA-PSS-3072 randomized KAT failed" : error);
    }

    std::cout << "[PASS] ecdsa-p256 deterministic sign/verify\n";
    std::cout << "[PASS] rsa-pss-3072 randomized sign/verify\n";
    return 0;
}

void print_help() {
    std::cout
        << "sigtool - Lab 5 classical digital signatures\n\n"
        << "Usage:\n"
        << "  sigtool keygen --algo ecdsa-p256|rsa-pss-3072 --pub pub.pem --priv priv.pem [--format pem|der] [--meta key.json]\n"
        << "  sigtool sign --algo ALG --priv priv.pem --in msg.bin --out sig.bin --hash sha256 [--encode der|raw|base64]\n"
        << "  sigtool verify --algo ALG --pub pub.pem --in msg.bin --sig sig.bin --hash sha256 [--encode der|raw|base64]\n"
        << "  sigtool batch-verify --algo ALG --pub pub.pem --manifest manifest.csv --hash sha256 [--encode der|raw|base64]\n"
        << "  sigtool kat\n"
        << "  sigtool bench --out raw.csv --summary summary.csv [--runs N] [--ops N] [--sizes 1k,16k,1m,8m]\n\n"
        << "Algorithms:\n"
        << "  ecdsa-p256     NIST P-256 / secp256r1, SHA-256, RFC6979 deterministic nonce\n"
        << "  rsa-pss-3072   RSA-3072, SHA-256, MGF1-SHA256, 32-byte randomized salt, e=65537\n\n"
        << "Defaults: PEM keys, ECDSA DER signatures, RSA raw signatures. Base64 writes ASCII signature bytes.\n";
}

} // namespace

int run_cli(int argc, char** argv) {
    if (argc <= 1 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h" || std::string(argv[1]) == "help") {
        print_help();
        return 0;
    }

    ParsedArgs args;
    std::string error;
    if (!parse_options(argc, argv, 2, args, error)) {
        return fail(error);
    }

    const std::string command = argv[1];
    if (command == "keygen") {
        return command_keygen(args);
    }
    if (command == "sign") {
        return command_sign(args);
    }
    if (command == "verify") {
        return command_verify(args, false);
    }
    if (command == "batch-verify") {
        return command_batch_verify(args);
    }
    if (command == "kat") {
        return command_kat(args);
    }
    if (command == "bench") {
        return command_bench(args);
    }
    return fail("unsupported command: " + command);
}

} // namespace sigtool
