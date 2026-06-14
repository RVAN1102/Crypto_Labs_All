#include "bench.hpp"

#include "cli.hpp"
#include "encoding.hpp"
#include "envelope.hpp"
#include "rsa_oaep.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static volatile std::size_t g_bench_sink = 0;

class XorShift32 {
public:
    explicit XorShift32(std::uint32_t seed)
        : state_(seed == 0 ? 0x12345678u : seed) {
    }

    unsigned char next_byte() {
        std::uint32_t x = state_;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state_ = x;
        return static_cast<unsigned char>(x & 0xffu);
    }

private:
    std::uint32_t state_;
};

struct RawRow {
    std::string platform;
    int rsa_bits;
    std::string family;
    std::string operation;
    std::size_t payload_bytes;
    int run_index;
    int ops;
    double total_ms;
    double ms_per_op;
    double throughput_mib_s;
};

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',') {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) {
        out.push_back(cur);
    }
    return out;
}

static std::size_t parse_size_token(std::string token) {
    if (token.empty()) {
        throw std::runtime_error("Empty size token.");
    }

    for (char& c : token) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    std::size_t mult = 1;
    if (token.back() == 'k') {
        mult = 1024;
        token.pop_back();
    } else if (token.back() == 'm') {
        mult = 1024 * 1024;
        token.pop_back();
    }

    try {
        return static_cast<std::size_t>(std::stoull(token)) * mult;
    } catch (...) {
        throw std::runtime_error("Invalid size token.");
    }
}

static std::vector<std::size_t> parse_sizes(const std::string& s) {
    std::vector<std::size_t> out;
    for (const std::string& token : split_csv(s)) {
        out.push_back(parse_size_token(token));
    }
    if (out.empty()) {
        throw std::runtime_error("No sizes provided.");
    }
    return out;
}

static std::vector<int> parse_bits_list(const std::string& s) {
    std::vector<int> out;
    for (const std::string& token : split_csv(s)) {
        try {
            out.push_back(std::stoi(token));
        } catch (...) {
            throw std::runtime_error("Invalid RSA bits token.");
        }
    }
    if (out.empty()) {
        throw std::runtime_error("No RSA bit sizes provided.");
    }
    return out;
}

static int parse_int_option(const std::map<std::string, std::string>& opts, const std::string& name, int fallback) {
    const auto it = opts.find(name);
    if (it == opts.end()) {
        return fallback;
    }
    try {
        const int value = std::stoi(it->second);
        if (value <= 0) {
            throw std::runtime_error("non-positive");
        }
        return value;
    } catch (...) {
        throw std::runtime_error("Invalid integer option --" + name);
    }
}

static std::string default_platform_label() {
#if defined(_WIN32)
    return "windows-mingw64";
#elif defined(__linux__)
    return "linux";
#elif defined(__APPLE__)
    return "macos";
#else
    return "unknown";
#endif
}

static Bytes synthetic_data(std::size_t n) {
    Bytes out(n);
    XorShift32 rng(0xC0FFEEu);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = rng.next_byte();
    }
    return out;
}

static double elapsed_ms(
    const std::chrono::steady_clock::time_point& a,
    const std::chrono::steady_clock::time_point& b
) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

static double throughput(std::size_t bytes, int ops, double total_ms) {
    if (total_ms <= 0.0) {
        return 0.0;
    }
    const double mib = (static_cast<double>(bytes) * static_cast<double>(ops)) / (1024.0 * 1024.0);
    return mib / (total_ms / 1000.0);
}

static double mean(const std::vector<double>& v) {
    double sum = 0.0;
    for (double x : v) {
        sum += x;
    }
    return v.empty() ? 0.0 : sum / static_cast<double>(v.size());
}

static double median(std::vector<double> v) {
    if (v.empty()) {
        return 0.0;
    }
    std::sort(v.begin(), v.end());
    const std::size_t n = v.size();
    if ((n % 2) == 1) {
        return v[n / 2];
    }
    return (v[(n / 2) - 1] + v[n / 2]) / 2.0;
}

static double stddev(const std::vector<double>& v) {
    if (v.size() < 2) {
        return 0.0;
    }
    const double m = mean(v);
    double sum = 0.0;
    for (double x : v) {
        const double d = x - m;
        sum += d * d;
    }
    return std::sqrt(sum / static_cast<double>(v.size() - 1));
}

static void write_raw_header(std::ofstream& out) {
    out << "platform,rsa_bits,family,operation,payload_bytes,run_index,ops,total_ms,ms_per_op,throughput_mib_s\n";
}

static void write_summary_header(std::ofstream& out) {
    out << "platform,rsa_bits,family,operation,payload_bytes,runs,ops_per_run,mean_ms_per_op,median_ms_per_op,stddev_ms_per_op,ci95_ms_per_op,mean_mib_s,median_mib_s,stddev_mib_s,ci95_mib_s\n";
}

static void write_raw_row(std::ofstream& out, const RawRow& row) {
    out << row.platform << ','
        << row.rsa_bits << ','
        << row.family << ','
        << row.operation << ','
        << row.payload_bytes << ','
        << row.run_index << ','
        << row.ops << ','
        << std::fixed << std::setprecision(6)
        << row.total_ms << ','
        << row.ms_per_op << ','
        << row.throughput_mib_s << '\n';
}

static void write_summary_row(
    std::ofstream& out,
    const std::string& platform,
    int bits,
    const std::string& family,
    const std::string& operation,
    std::size_t payload_size,
    int runs,
    int ops,
    const std::vector<double>& ms_values,
    const std::vector<double>& mib_values
) {
    const double mean_ms = mean(ms_values);
    const double median_ms = median(ms_values);
    const double sd_ms = stddev(ms_values);
    const double ci_ms = runs > 1 ? 1.96 * sd_ms / std::sqrt(static_cast<double>(runs)) : 0.0;
    const double mean_mib = mean(mib_values);
    const double median_mib = median(mib_values);
    const double sd_mib = stddev(mib_values);
    const double ci_mib = runs > 1 ? 1.96 * sd_mib / std::sqrt(static_cast<double>(runs)) : 0.0;

    out << platform << ','
        << bits << ','
        << family << ','
        << operation << ','
        << payload_size << ','
        << runs << ','
        << ops << ','
        << std::fixed << std::setprecision(6)
        << mean_ms << ','
        << median_ms << ','
        << sd_ms << ','
        << ci_ms << ','
        << mean_mib << ','
        << median_mib << ','
        << sd_mib << ','
        << ci_mib << '\n';
}

template <class Fn>
static void run_case(
    std::ofstream& raw,
    std::ofstream& summary,
    const std::string& platform,
    int bits,
    const std::string& family,
    const std::string& operation,
    std::size_t payload_size,
    int runs,
    int ops,
    Fn fn
) {
    std::vector<double> ms_values;
    std::vector<double> mib_values;

    for (int run = 1; run <= runs; ++run) {
        const auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < ops; ++i) {
            g_bench_sink += fn().size();
        }
        const auto end = std::chrono::steady_clock::now();

        const double total = elapsed_ms(start, end);
        const double ms = total / static_cast<double>(ops);
        const double mib = throughput(payload_size, ops, total);
        ms_values.push_back(ms);
        mib_values.push_back(mib);

        RawRow row{platform, bits, family, operation, payload_size, run, ops, total, ms, mib};
        write_raw_row(raw, row);
    }

    write_summary_row(summary, platform, bits, family, operation, payload_size, runs, ops, ms_values, mib_values);
}

void command_bench(const std::map<std::string, std::string>& opts) {
    const std::string out_path = require_option(opts, "out");
    const std::string summary_path = get_option_or(opts, "summary", out_path + ".summary.csv");
    const std::string platform = get_option_or(opts, "platform", default_platform_label());
    const int runs = parse_int_option(opts, "runs", 10);
    const int ops = parse_int_option(opts, "ops", 10);
    const std::vector<int> bits_list = parse_bits_list(get_option_or(opts, "rsa-bits", "3072,4096"));
    const std::vector<std::size_t> rsa_sizes = parse_sizes(get_option_or(opts, "rsa-sizes", "32,190,318"));
    const std::vector<std::size_t> hybrid_sizes = parse_sizes(get_option_or(opts, "sizes", "1k,16k,256k,1m"));
    const Bytes label{'l', 'a', 'b', '3', '-', 'b', 'e', 'n', 'c', 'h'};

    std::ofstream raw(out_path, std::ios::binary);
    if (!raw) {
        throw std::runtime_error("Cannot open raw benchmark CSV: " + out_path);
    }
    std::ofstream summary(summary_path, std::ios::binary);
    if (!summary) {
        throw std::runtime_error("Cannot open summary benchmark CSV: " + summary_path);
    }

    write_raw_header(raw);
    write_summary_header(summary);

    std::cout << "Benchmark raw CSV: " << out_path << "\n";
    std::cout << "Benchmark summary CSV: " << summary_path << "\n";
    std::cout << "Runs=" << runs << ", ops=" << ops << "\n";

    for (int bits : bits_list) {
        std::cout << "Generating RSA-" << bits << " benchmark key...\n";
        const RsaKeyPairDer keys = generate_rsa_keypair_der(bits);

        for (std::size_t size : rsa_sizes) {
            if (size > rsa_oaep_sha256_max_plaintext_for_bits(bits)) {
                continue;
            }

            const Bytes payload = synthetic_data(size);
            const Bytes ciphertext = rsa_oaep_sha256_encrypt_der(keys.public_key_der, payload, label);

            std::cout << "RSA-OAEP bits=" << bits << " size=" << size << "\n";
            run_case(raw, summary, platform, bits, "rsa-oaep", "encrypt", size, runs, ops, [&]() {
                return rsa_oaep_sha256_encrypt_der(keys.public_key_der, payload, label);
            });
            run_case(raw, summary, platform, bits, "rsa-oaep", "decrypt", size, runs, ops, [&]() {
                return rsa_oaep_sha256_decrypt_der(keys.private_key_der, ciphertext, label);
            });
        }

        for (std::size_t size : hybrid_sizes) {
            const Bytes payload = synthetic_data(size);
            const HybridEncryptResult sealed = hybrid_encrypt(keys.public_key_der, payload, label, "bench.ct");

            std::cout << "Hybrid bits=" << bits << " size=" << size << "\n";
            run_case(raw, summary, platform, bits, "hybrid", "encrypt", size, runs, ops, [&]() {
                const HybridEncryptResult out = hybrid_encrypt(keys.public_key_der, payload, label, "bench.ct");
                return out.ciphertext;
            });
            run_case(raw, summary, platform, bits, "hybrid", "decrypt", size, runs, ops, [&]() {
                return hybrid_decrypt(keys.private_key_der, sealed.ciphertext, sealed.envelope, label);
            });
        }
    }

    std::cout << "Benchmark completed. Anti-optimization sink: " << g_bench_sink << "\n";
}
