#include "hashtool/cli.hpp"

#include "hashtool/bench.hpp"
#include "hashtool/cert.hpp"
#include "hashtool/encoding.hpp"
#include "hashtool/file_utils.hpp"
#include "hashtool/hash.hpp"
#include "hashtool/kat.hpp"
#include "hashtool/mac.hpp"

#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace hashtool {

namespace {

struct ParsedArgs {
    std::map<std::string, std::string> values;
    bool stream = false;
};

void print_help() {
    std::cout
        << "hashtool - Lab 4 hash and MAC CLI\n"
        << "\n"
        << "Usage:\n"
        << "  hashtool --help\n"
        << "  hashtool hash --algo ALG (--text TEXT | --in FILE) [--stream] [--out FILE] [--encode hex|base64|raw] [--outlen N]\n"
        << "  hashtool kat --kat FILE\n"
        << "  hashtool naive-mac --algo ALG --key-hex HEX (--text TEXT | --in FILE) [--out FILE] [--encode hex|base64|raw]\n"
        << "  hashtool hmac --algo ALG --key-hex HEX (--text TEXT | --in FILE) [--out FILE] [--encode hex|base64|raw]\n"
        << "  hashtool hmac-verify --algo ALG --key-hex HEX (--text TEXT | --in FILE) --mac-hex HEX\n"
        << "  hashtool cert-info --cert FILE [--format pem|der] [--json FILE]\n"
        << "  hashtool cert-verify --cert FILE [--format pem|der] [--issuer FILE] [--issuer-format pem|der]\n"
        << "  hashtool cert-policy --cert FILE [--format pem|der]\n"
        << "  hashtool bench --out FILE --summary FILE --runs N --ops N --warmup-ms N --sizes LIST --algos LIST --platform NAME\n"
        << "\n"
        << "Algorithms: sha224 sha256 sha384 sha512 sha3-224 sha3-256 sha3-384 sha3-512 shake128 shake256\n";
}

bool parse_options(int argc, char** argv, int start, ParsedArgs& parsed, std::string& error) {
    parsed = ParsedArgs{};
    for (int i = start; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--stream") {
            parsed.stream = true;
            continue;
        }

        if (arg.rfind("--", 0) != 0) {
            error = "unexpected positional argument: " + arg;
            return false;
        }

        if (i + 1 >= argc) {
            error = "missing value for " + arg;
            return false;
        }

        const std::string key = arg.substr(2);
        if (parsed.values.find(key) != parsed.values.end()) {
            error = "duplicate option: " + arg;
            return false;
        }
        parsed.values[key] = argv[++i];
    }
    return true;
}

bool require_option(const ParsedArgs& args, const std::string& name, std::string& value, std::string& error) {
    const auto it = args.values.find(name);
    if (it == args.values.end()) {
        error = "missing required option --" + name;
        return false;
    }
    value = it->second;
    return true;
}

bool parse_outlen(const ParsedArgs& args, bool& present, std::size_t& outlen, std::string& error) {
    present = false;
    outlen = 0;
    const auto it = args.values.find("outlen");
    if (it == args.values.end()) {
        return true;
    }

    present = true;
    try {
        std::size_t consumed = 0;
        const unsigned long long value = std::stoull(it->second, &consumed, 10);
        if (consumed != it->second.size() || value == 0 || value > 1024ULL * 1024ULL) {
            error = "invalid --outlen";
            return false;
        }
        outlen = static_cast<std::size_t>(value);
        return true;
    } catch (...) {
        error = "invalid --outlen";
        return false;
    }
}

bool load_input(const ParsedArgs& args, Bytes& input, std::string& input_path, bool& use_file, std::string& error) {
    const bool has_text = args.values.find("text") != args.values.end();
    const bool has_in = args.values.find("in") != args.values.end();
    if (has_text == has_in) {
        error = has_text ? "rejecting both --in and --text" : "missing input: supply --in or --text";
        return false;
    }

    use_file = has_in;
    if (has_text) {
        const std::string& text = args.values.at("text");
        input.assign(text.begin(), text.end());
        return true;
    }

    input_path = args.values.at("in");
    if (args.stream) {
        input.clear();
        return true;
    }
    return read_binary_file(input_path, input, error);
}

bool choose_encoding(const ParsedArgs& args, Encoding& encoding, std::string& error) {
    encoding = Encoding::Hex;
    const auto it = args.values.find("encode");
    if (it == args.values.end()) {
        return true;
    }
    if (!parse_encoding(it->second, encoding)) {
        error = "invalid encoding";
        return false;
    }
    return true;
}

bool output_bytes(const ParsedArgs& args, const Bytes& bytes, std::string& error) {
    Encoding encoding;
    if (!choose_encoding(args, encoding, error)) {
        return false;
    }

    const auto out_it = args.values.find("out");
    const bool has_out = out_it != args.values.end();
    if (encoding == Encoding::Raw) {
        if (!has_out) {
            error = "raw output requires --out";
            return false;
        }
        return write_binary_file(out_it->second, bytes, error);
    }

    const std::string rendered = encoding == Encoding::Hex ? hex_encode(bytes) : base64_encode(bytes);
    if (has_out) {
        return write_text_file(out_it->second, rendered + "\n", error);
    }

    std::cout << rendered << "\n";
    return true;
}

bool parse_algorithm_from_args(const ParsedArgs& args, HashAlgorithm& algorithm, std::string& error) {
    std::string algo;
    if (!require_option(args, "algo", algo, error)) {
        return false;
    }
    if (!parse_hash_algorithm(algo, algorithm)) {
        error = "unsupported algorithm";
        return false;
    }
    return true;
}

int fail(const std::string& error) {
    std::cerr << "error: " << error << "\n";
    return 1;
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::vector<std::string> split_csv(const std::string& text) {
    std::vector<std::string> values;
    std::stringstream ss(text);
    std::string item;
    while (std::getline(ss, item, ',')) {
        values.push_back(item);
    }
    return values;
}

bool parse_positive_int_option(const ParsedArgs& args, const std::string& name, int& value, std::string& error) {
    std::string text;
    if (!require_option(args, name, text, error)) {
        return false;
    }
    try {
        std::size_t consumed = 0;
        const long parsed = std::stol(text, &consumed, 10);
        if (consumed != text.size() || parsed <= 0 || parsed > 1000000) {
            error = "invalid --" + name;
            return false;
        }
        value = static_cast<int>(parsed);
        return true;
    } catch (...) {
        error = "invalid --" + name;
        return false;
    }
}

bool parse_nonnegative_int_option(const ParsedArgs& args, const std::string& name, int& value, std::string& error) {
    std::string text;
    if (!require_option(args, name, text, error)) {
        return false;
    }
    try {
        std::size_t consumed = 0;
        const long parsed = std::stol(text, &consumed, 10);
        if (consumed != text.size() || parsed < 0 || parsed > 3600000) {
            error = "invalid --" + name;
            return false;
        }
        value = static_cast<int>(parsed);
        return true;
    } catch (...) {
        error = "invalid --" + name;
        return false;
    }
}

bool parse_bench_size(const std::string& text, std::size_t& size) {
    const std::string lower = lowercase(text);
    if (lower == "1k") {
        size = 1024ULL;
        return true;
    }
    if (lower == "4k") {
        size = 4ULL * 1024ULL;
        return true;
    }
    if (lower == "1m") {
        size = 1024ULL * 1024ULL;
        return true;
    }
    if (lower == "100m") {
        size = 100ULL * 1024ULL * 1024ULL;
        return true;
    }
    if (lower == "1g") {
        size = 1024ULL * 1024ULL * 1024ULL;
        return true;
    }
    return false;
}

int run_hash_command(const ParsedArgs& args) {
    std::string error;
    HashAlgorithm algorithm;
    if (!parse_algorithm_from_args(args, algorithm, error)) {
        return fail(error);
    }

    bool has_outlen = false;
    std::size_t outlen = 0;
    if (!parse_outlen(args, has_outlen, outlen, error)) {
        return fail(error);
    }
    if (algorithm.is_shake && !has_outlen) {
        return fail("SHAKE requires --outlen");
    }
    if (!algorithm.is_shake && has_outlen) {
        return fail("fixed SHA-2/SHA-3 hashes reject --outlen");
    }

    Bytes input;
    std::string input_path;
    bool use_file = false;
    if (!load_input(args, input, input_path, use_file, error)) {
        return fail(error);
    }

    Bytes digest;
    const bool ok = use_file && args.stream
        ? hash_file_streaming(algorithm, input_path, outlen, digest, error)
        : hash_bytes(algorithm, input, outlen, digest, error);
    if (!ok) {
        return fail(error);
    }

    if (!output_bytes(args, digest, error)) {
        return fail(error);
    }
    return 0;
}

int run_mac_command(const ParsedArgs& args, bool naive) {
    std::string error;
    HashAlgorithm algorithm;
    if (!parse_algorithm_from_args(args, algorithm, error)) {
        return fail(error);
    }

    std::string key_hex;
    if (!require_option(args, "key-hex", key_hex, error)) {
        return fail(error);
    }
    Bytes key;
    if (!hex_decode(key_hex, key, error)) {
        return fail("malformed key-hex: " + error);
    }

    Bytes input;
    std::string input_path;
    bool use_file = false;
    if (!load_input(args, input, input_path, use_file, error)) {
        return fail(error);
    }
    if (use_file && args.stream && !read_binary_file(input_path, input, error)) {
        return fail(error);
    }

    Bytes mac;
    const bool ok = naive
        ? naive_mac_bytes(algorithm, key, input, mac, error)
        : hmac_bytes(algorithm, key, input, mac, error);
    if (!ok) {
        return fail(error);
    }

    if (naive) {
        std::cerr << "WARNING: naive MAC H(k || m) is vulnerable to length-extension attacks. Use HMAC.\n";
    }

    if (!output_bytes(args, mac, error)) {
        return fail(error);
    }
    return 0;
}

int run_hmac_verify_command(const ParsedArgs& args) {
    std::string error;
    HashAlgorithm algorithm;
    if (!parse_algorithm_from_args(args, algorithm, error)) {
        return fail(error);
    }

    std::string key_hex;
    if (!require_option(args, "key-hex", key_hex, error)) {
        return fail(error);
    }
    Bytes key;
    if (!hex_decode(key_hex, key, error)) {
        return fail("malformed key-hex: " + error);
    }

    std::string mac_hex;
    if (!require_option(args, "mac-hex", mac_hex, error)) {
        return fail(error);
    }
    Bytes expected_mac;
    if (!hex_decode(mac_hex, expected_mac, error)) {
        return fail("malformed mac-hex: " + error);
    }

    Bytes input;
    std::string input_path;
    bool use_file = false;
    if (!load_input(args, input, input_path, use_file, error)) {
        return fail(error);
    }
    if (use_file && args.stream && !read_binary_file(input_path, input, error)) {
        return fail(error);
    }

    bool verified = false;
    if (!verify_hmac_bytes(algorithm, key, input, expected_mac, verified, error)) {
        return fail(error);
    }

    if (verified) {
        std::cout << "[PASS] HMAC verified\n";
        return 0;
    }
    std::cout << "[FAIL] HMAC verification failed\n";
    return 1;
}

std::string optional_format(const ParsedArgs& args, const std::string& key) {
    const auto it = args.values.find(key);
    return it == args.values.end() ? "pem" : it->second;
}

int run_cert_info_command(const ParsedArgs& args) {
    std::string error;
    std::string cert_path;
    if (!require_option(args, "cert", cert_path, error)) {
        return fail(error);
    }

    CertInfo info;
    if (!get_cert_info(cert_path, optional_format(args, "format"), info, error)) {
        return fail(error);
    }

    const auto json_it = args.values.find("json");
    if (json_it != args.values.end()) {
        if (!write_text_file(json_it->second, cert_info_to_json(info), error)) {
            return fail(error);
        }
    }

    std::cout << cert_info_to_text(info);
    return 0;
}

int run_cert_verify_command(const ParsedArgs& args) {
    std::string error;
    std::string cert_path;
    if (!require_option(args, "cert", cert_path, error)) {
        return fail(error);
    }

    std::string output;
    const auto issuer_it = args.values.find("issuer");
    if (issuer_it == args.values.end()) {
        if (!limited_certificate_readability_check(cert_path, optional_format(args, "format"), output, error)) {
            return fail(error);
        }
    } else if (!verify_certificate_signature(
                   cert_path,
                   optional_format(args, "format"),
                   issuer_it->second,
                   optional_format(args, "issuer-format"),
                   output,
                   error)) {
        return fail(error);
    }

    std::cout << output;
    return 0;
}

int run_cert_policy_command(const ParsedArgs& args) {
    std::string error;
    std::string cert_path;
    if (!require_option(args, "cert", cert_path, error)) {
        return fail(error);
    }

    std::string output;
    if (!run_certificate_policy(cert_path, optional_format(args, "format"), output, error)) {
        return fail(error);
    }

    std::cout << output;
    return 0;
}

int run_bench_command(const ParsedArgs& args) {
    std::string error;
    BenchConfig config;
    if (!require_option(args, "out", config.out_path, error) ||
        !require_option(args, "summary", config.summary_path, error) ||
        !parse_positive_int_option(args, "runs", config.runs, error) ||
        !parse_positive_int_option(args, "ops", config.ops, error) ||
        !parse_nonnegative_int_option(args, "warmup-ms", config.warmup_ms, error) ||
        !require_option(args, "platform", config.platform, error)) {
        return fail(error);
    }

    std::string algos_text;
    if (!require_option(args, "algos", algos_text, error)) {
        return fail(error);
    }
    if (algos_text.empty()) {
        return fail("empty --algos");
    }
    for (const auto& algo : split_csv(algos_text)) {
        const auto lower = lowercase(algo);
        if (lower.empty()) {
            return fail("empty --algos");
        }
        if (lower != "sha256" && lower != "sha512" && lower != "sha3-256" && lower != "sha3-512") {
            return fail("unsupported benchmark algorithm: " + algo);
        }
        config.algos.push_back(lower);
    }

    std::string sizes_text;
    if (!require_option(args, "sizes", sizes_text, error)) {
        return fail(error);
    }
    if (sizes_text.empty()) {
        return fail("empty --sizes");
    }
    for (const auto& size_text : split_csv(sizes_text)) {
        std::size_t size = 0;
        if (size_text.empty() || !parse_bench_size(size_text, size)) {
            return fail("invalid size: " + size_text);
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

} // namespace

int run_cli(int argc, char** argv) {
    if (argc <= 1 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        print_help();
        return 0;
    }

    const std::string command = argv[1];
    ParsedArgs args;
    std::string error;
    if (!parse_options(argc, argv, 2, args, error)) {
        return fail(error);
    }

    if (command == "hash") {
        return run_hash_command(args);
    }
    if (command == "kat") {
        std::string path;
        if (!require_option(args, "kat", path, error)) {
            return fail(error);
        }
        return run_kat_file(path);
    }
    if (command == "naive-mac") {
        return run_mac_command(args, true);
    }
    if (command == "hmac") {
        return run_mac_command(args, false);
    }
    if (command == "hmac-verify") {
        return run_hmac_verify_command(args);
    }
    if (command == "cert-info") {
        return run_cert_info_command(args);
    }
    if (command == "cert-verify") {
        return run_cert_verify_command(args);
    }
    if (command == "cert-policy") {
        return run_cert_policy_command(args);
    }
    if (command == "bench") {
        return run_bench_command(args);
    }

    return fail("unsupported command");
}

} // namespace hashtool
