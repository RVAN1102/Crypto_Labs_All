#include <functional>
#include "bench.hpp"

#include "aes_ccm.hpp"
#include "aes_classic.hpp"
#include "aes_gcm.hpp"
#include "aes_xts.hpp"
#include "cli.hpp"
#include "crypto_utils.hpp"
#include "encoding.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static volatile std::size_t g_bench_sink = 0;

class XorShift32 {
public:
    explicit XorShift32(uint32_t seed)
        : state_(seed == 0 ? 0x12345678u : seed) {
    }

    uint32_t next_u32() {
        uint32_t x = state_;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state_ = x;
        return x;
    }

    unsigned char next_byte() {
        return static_cast<unsigned char>(next_u32() & 0xffu);
    }

private:
    uint32_t state_;
};

struct BenchCaseResult {
    std::string platform;
    std::string mode;
    std::string operation;
    std::size_t payload_bytes;
    int run_index;
    int ops;
    double total_ms;
    double ms_per_op;
    double throughput_mib_s;
};

struct SummaryResult {
    std::string platform;
    std::string mode;
    std::string operation;
    std::size_t payload_bytes;
    int runs;
    int ops_per_run;

    double mean_ms_per_op;
    double median_ms_per_op;
    double stddev_ms_per_op;
    double ci95_ms_per_op;

    double mean_mib_s;
    double median_mib_s;
    double stddev_mib_s;
    double ci95_mib_s;
};

static std::vector<std::string> split_csv_string(const std::string& s) {
    std::vector<std::string> out;
    std::string current;

    for (char c : s) {
        if (c == ',') {
            if (!current.empty()) {
                out.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }

    if (!current.empty()) {
        out.push_back(current);
    }

    return out;
}

static std::string lower_copy(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }

    return s;
}

static std::size_t parse_size_token(std::string token) {
    token = lower_copy(token);

    if (token.empty()) {
        throw std::runtime_error("Empty size token.");
    }

    std::size_t multiplier = 1;

    if (token.back() == 'k') {
        multiplier = 1024;
        token.pop_back();
    } else if (token.back() == 'm') {
        multiplier = 1024 * 1024;
        token.pop_back();
    }

    if (token.empty()) {
        throw std::runtime_error("Invalid size token.");
    }

    std::size_t value = 0;

    try {
        value = static_cast<std::size_t>(std::stoull(token));
    } catch (...) {
        throw std::runtime_error("Invalid size token.");
    }

    return value * multiplier;
}

static std::vector<std::size_t> parse_sizes(const std::string& s) {
    std::vector<std::size_t> sizes;

    for (const std::string& token : split_csv_string(s)) {
        sizes.push_back(parse_size_token(token));
    }

    if (sizes.empty()) {
        throw std::runtime_error("No payload sizes provided.");
    }

    return sizes;
}

static int parse_int_option(
    const std::map<std::string, std::string>& opts,
    const std::string& name,
    int default_value
) {
    auto it = opts.find(name);

    if (it == opts.end()) {
        return default_value;
    }

    try {
        int value = std::stoi(it->second);

        if (value <= 0) {
            throw std::runtime_error("non-positive value");
        }

        return value;
    } catch (...) {
        throw std::runtime_error("Invalid integer option --" + name);
    }
}

static Bytes make_synthetic_data(std::size_t n) {
    Bytes data(n);
    XorShift32 prng(0xC0FFEEu);

    for (std::size_t i = 0; i < n; ++i) {
        data[i] = prng.next_byte();
    }

    return data;
}

static void put_counter_tail(Bytes& block, uint64_t counter) {
    if (block.empty()) {
        return;
    }

    const std::size_t n = block.size();

    for (std::size_t i = 0; i < 8 && i < n; ++i) {
        block[n - 1 - i] = static_cast<unsigned char>((counter >> (8 * i)) & 0xffu);
    }
}

static double elapsed_ms(
    const std::chrono::steady_clock::time_point& start,
    const std::chrono::steady_clock::time_point& end
) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

static void warmup_for_ms(const std::function<void()>& fn, int warmup_ms) {
    const auto start = std::chrono::steady_clock::now();

    while (true) {
        fn();

        const auto now = std::chrono::steady_clock::now();
        if (elapsed_ms(start, now) >= static_cast<double>(warmup_ms)) {
            break;
        }
    }
}

static double mean_value(const std::vector<double>& v) {
    if (v.empty()) {
        return 0.0;
    }

    double sum = 0.0;

    for (double x : v) {
        sum += x;
    }

    return sum / static_cast<double>(v.size());
}

static double median_value(std::vector<double> v) {
    if (v.empty()) {
        return 0.0;
    }

    std::sort(v.begin(), v.end());

    const std::size_t n = v.size();

    if (n % 2 == 1) {
        return v[n / 2];
    }

    return (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

static double stddev_value(const std::vector<double>& v) {
    if (v.size() < 2) {
        return 0.0;
    }

    const double m = mean_value(v);
    double sum_sq = 0.0;

    for (double x : v) {
        const double d = x - m;
        sum_sq += d * d;
    }

    return std::sqrt(sum_sq / static_cast<double>(v.size() - 1));
}

static double ci95_value(const std::vector<double>& v) {
    if (v.size() < 2) {
        return 0.0;
    }

    return 1.96 * stddev_value(v) / std::sqrt(static_cast<double>(v.size()));
}

static SummaryResult summarize_case(
    const std::string& platform,
    const std::string& mode,
    const std::string& operation,
    std::size_t payload_bytes,
    int runs,
    int ops,
    const std::vector<double>& ms_per_op_values,
    const std::vector<double>& throughput_values
) {
    SummaryResult s;

    s.platform = platform;
    s.mode = mode;
    s.operation = operation;
    s.payload_bytes = payload_bytes;
    s.runs = runs;
    s.ops_per_run = ops;

    s.mean_ms_per_op = mean_value(ms_per_op_values);
    s.median_ms_per_op = median_value(ms_per_op_values);
    s.stddev_ms_per_op = stddev_value(ms_per_op_values);
    s.ci95_ms_per_op = ci95_value(ms_per_op_values);

    s.mean_mib_s = mean_value(throughput_values);
    s.median_mib_s = median_value(throughput_values);
    s.stddev_mib_s = stddev_value(throughput_values);
    s.ci95_mib_s = ci95_value(throughput_values);

    return s;
}

static double throughput_mib_s(std::size_t payload_bytes, int ops, double total_ms) {
    const double total_bytes = static_cast<double>(payload_bytes) * static_cast<double>(ops);
    const double seconds = total_ms / 1000.0;

    if (seconds <= 0.0) {
        return 0.0;
    }

    return (total_bytes / (1024.0 * 1024.0)) / seconds;
}

static void append_raw_csv_header(std::ofstream& out) {
    out << "platform,mode,operation,payload_bytes,run,ops,total_ms,ms_per_op,throughput_mib_s\n";
}

static void append_summary_csv_header(std::ofstream& out) {
    out << "platform,mode,operation,payload_bytes,runs,ops_per_run,"
        << "mean_ms_per_op,median_ms_per_op,stddev_ms_per_op,ci95_ms_per_op,"
        << "mean_mib_s,median_mib_s,stddev_mib_s,ci95_mib_s\n";
}

static void write_raw_row(std::ofstream& out, const BenchCaseResult& r) {
    out << r.platform << ","
        << r.mode << ","
        << r.operation << ","
        << r.payload_bytes << ","
        << r.run_index << ","
        << r.ops << ","
        << std::fixed << std::setprecision(6) << r.total_ms << ","
        << std::fixed << std::setprecision(9) << r.ms_per_op << ","
        << std::fixed << std::setprecision(6) << r.throughput_mib_s
        << "\n";
}

static void write_summary_row(std::ofstream& out, const SummaryResult& s) {
    out << s.platform << ","
        << s.mode << ","
        << s.operation << ","
        << s.payload_bytes << ","
        << s.runs << ","
        << s.ops_per_run << ","
        << std::fixed << std::setprecision(9) << s.mean_ms_per_op << ","
        << std::fixed << std::setprecision(9) << s.median_ms_per_op << ","
        << std::fixed << std::setprecision(9) << s.stddev_ms_per_op << ","
        << std::fixed << std::setprecision(9) << s.ci95_ms_per_op << ","
        << std::fixed << std::setprecision(6) << s.mean_mib_s << ","
        << std::fixed << std::setprecision(6) << s.median_mib_s << ","
        << std::fixed << std::setprecision(6) << s.stddev_mib_s << ","
        << std::fixed << std::setprecision(6) << s.ci95_mib_s
        << "\n";
}

static void bench_classic_one_run(
    const std::string& mode,
    const std::string& operation,
    const Bytes& key,
    const Bytes& payload,
    int ops
) {
    Bytes iv_base = random_bytes(16);
    Bytes iv = iv_base;

    if (operation == "encrypt") {
        for (int i = 0; i < ops; ++i) {
            iv = iv_base;
            put_counter_tail(iv, static_cast<uint64_t>(i));

            Bytes out = aes_encrypt_classic(
                mode,
                key,
                mode == "ecb" ? Bytes{} : iv,
                payload,
                true,
                true
            );

            g_bench_sink += out.size();
        }
    } else if (operation == "decrypt") {
        Bytes fixed_iv = iv_base;
        Bytes ciphertext = aes_encrypt_classic(
            mode,
            key,
            mode == "ecb" ? Bytes{} : fixed_iv,
            payload,
            true,
            true
        );

        for (int i = 0; i < ops; ++i) {
            Bytes out = aes_decrypt_classic(
                mode,
                key,
                mode == "ecb" ? Bytes{} : fixed_iv,
                ciphertext,
                true
            );

            g_bench_sink += out.size();
        }
    } else {
        throw std::runtime_error("Unsupported benchmark operation.");
    }
}

static void bench_gcm_one_run(
    const std::string& operation,
    const Bytes& key,
    const Bytes& payload,
    int ops
) {
    const Bytes aad = make_synthetic_data(32);
    Bytes nonce_base = random_bytes(12);
    Bytes nonce = nonce_base;

    if (operation == "encrypt") {
        for (int i = 0; i < ops; ++i) {
            nonce = nonce_base;
            put_counter_tail(nonce, static_cast<uint64_t>(i));

            Bytes ct;
            Bytes tag;

            aes_gcm_encrypt(key, nonce, aad, payload, ct, tag);

            g_bench_sink += ct.size() + tag.size();
        }
    } else if (operation == "decrypt") {
        Bytes ct;
        Bytes tag;

        aes_gcm_encrypt(key, nonce_base, aad, payload, ct, tag);

        for (int i = 0; i < ops; ++i) {
            Bytes out = aes_gcm_decrypt(key, nonce_base, aad, ct, tag);
            g_bench_sink += out.size();
        }
    } else {
        throw std::runtime_error("Unsupported benchmark operation.");
    }
}

static void bench_ccm_one_run(
    const std::string& operation,
    const Bytes& key,
    const Bytes& payload,
    int ops
) {
    const Bytes aad = make_synthetic_data(32);
    Bytes nonce_base = random_bytes(12);
    Bytes nonce = nonce_base;

    if (operation == "encrypt") {
        for (int i = 0; i < ops; ++i) {
            nonce = nonce_base;
            put_counter_tail(nonce, static_cast<uint64_t>(i));

            Bytes ct;
            Bytes tag;

            aes_ccm_encrypt(key, nonce, aad, payload, ct, tag);

            g_bench_sink += ct.size() + tag.size();
        }
    } else if (operation == "decrypt") {
        Bytes ct;
        Bytes tag;

        aes_ccm_encrypt(key, nonce_base, aad, payload, ct, tag);

        for (int i = 0; i < ops; ++i) {
            Bytes out = aes_ccm_decrypt(key, nonce_base, aad, ct, tag);
            g_bench_sink += out.size();
        }
    } else {
        throw std::runtime_error("Unsupported benchmark operation.");
    }
}

static void bench_xts_one_run(
    const std::string& operation,
    const Bytes& key,
    const Bytes& payload,
    int ops
) {
    Bytes tweak_base = random_bytes(16);
    Bytes tweak = tweak_base;

    if (operation == "encrypt") {
        for (int i = 0; i < ops; ++i) {
            tweak = tweak_base;
            put_counter_tail(tweak, static_cast<uint64_t>(i));

            Bytes out = aes_xts_encrypt(key, tweak, payload);
            g_bench_sink += out.size();
        }
    } else if (operation == "decrypt") {
        Bytes ct = aes_xts_encrypt(key, tweak_base, payload);

        for (int i = 0; i < ops; ++i) {
            Bytes out = aes_xts_decrypt(key, tweak_base, ct);
            g_bench_sink += out.size();
        }
    } else {
        throw std::runtime_error("Unsupported benchmark operation.");
    }
}

static void bench_one_run(
    const std::string& mode,
    const std::string& operation,
    const Bytes& key,
    const Bytes& xts_key,
    const Bytes& payload,
    int ops
) {
    if (mode == "ecb" ||
        mode == "cbc" ||
        mode == "cfb" ||
        mode == "ofb" ||
        mode == "ctr") {
        bench_classic_one_run(mode, operation, key, payload, ops);
        return;
    }

    if (mode == "gcm") {
        bench_gcm_one_run(operation, key, payload, ops);
        return;
    }

    if (mode == "ccm") {
        bench_ccm_one_run(operation, key, payload, ops);
        return;
    }

    if (mode == "xts") {
        bench_xts_one_run(operation, xts_key, payload, ops);
        return;
    }

    throw std::runtime_error("Unsupported benchmark mode: " + mode);
}

void command_bench(const std::map<std::string, std::string>& opts) {
    const std::string out_path = require_option(opts, "out");
    const std::string summary_path = opts.count("summary")
        ? opts.at("summary")
        : out_path + ".summary.csv";

    const std::string platform = opts.count("platform")
        ? opts.at("platform")
        : "windows-mingw64";

    const int runs = parse_int_option(opts, "runs", 30);
    const int ops = parse_int_option(opts, "ops", 1000);
    const int warmup_ms = parse_int_option(opts, "warmup-ms", 1000);

    const std::string modes_s = opts.count("modes")
        ? opts.at("modes")
        : "ecb,cbc,cfb,ofb,ctr,gcm,ccm,xts";

    const std::string sizes_s = opts.count("sizes")
        ? opts.at("sizes")
        : "1k,4k,16k,256k,1m,8m";

    const std::vector<std::string> modes = split_csv_string(modes_s);
    const std::vector<std::size_t> sizes = parse_sizes(sizes_s);

    Bytes key = random_bytes(32);
    Bytes xts_key = random_bytes(64);

    std::ofstream raw_out(out_path, std::ios::binary);
    if (!raw_out) {
        throw std::runtime_error("Cannot open benchmark CSV output: " + out_path);
    }

    std::ofstream summary_out(summary_path, std::ios::binary);
    if (!summary_out) {
        throw std::runtime_error("Cannot open benchmark summary CSV output: " + summary_path);
    }

    append_raw_csv_header(raw_out);
    append_summary_csv_header(summary_out);

    std::cout << "Benchmark output: " << out_path << "\n";
    std::cout << "Benchmark summary: " << summary_path << "\n";
    std::cout << "Platform label: " << platform << "\n";
    std::cout << "Runs=" << runs << ", ops=" << ops << ", warmup_ms=" << warmup_ms << "\n";
    std::cout << "Modes=" << modes_s << "\n";
    std::cout << "Sizes=" << sizes_s << "\n\n";

    const std::vector<std::string> operations = {"encrypt", "decrypt"};

    for (const std::string& raw_mode : modes) {
        const std::string mode = lower_copy(raw_mode);

        for (std::size_t payload_size : sizes) {
            if (mode == "xts" && payload_size < 16) {
                continue;
            }

            Bytes payload = make_synthetic_data(payload_size);

            for (const std::string& operation : operations) {
                std::cout << "Running mode=" << mode
                          << ", operation=" << operation
                          << ", size=" << payload_size
                          << " bytes...\n";

                auto one_op_block = [&]() {
                    bench_one_run(mode, operation, key, xts_key, payload, 1);
                };

                warmup_for_ms(one_op_block, warmup_ms);

                std::vector<double> ms_per_op_values;
                std::vector<double> throughput_values;

                for (int run = 1; run <= runs; ++run) {
                    const auto start = std::chrono::steady_clock::now();

                    bench_one_run(mode, operation, key, xts_key, payload, ops);

                    const auto end = std::chrono::steady_clock::now();

                    const double total_ms = elapsed_ms(start, end);
                    const double ms_per_op = total_ms / static_cast<double>(ops);
                    const double mib_s = throughput_mib_s(payload_size, ops, total_ms);

                    BenchCaseResult row;
                    row.platform = platform;
                    row.mode = mode;
                    row.operation = operation;
                    row.payload_bytes = payload_size;
                    row.run_index = run;
                    row.ops = ops;
                    row.total_ms = total_ms;
                    row.ms_per_op = ms_per_op;
                    row.throughput_mib_s = mib_s;

                    write_raw_row(raw_out, row);

                    ms_per_op_values.push_back(ms_per_op);
                    throughput_values.push_back(mib_s);
                }

                SummaryResult summary = summarize_case(
                    platform,
                    mode,
                    operation,
                    payload_size,
                    runs,
                    ops,
                    ms_per_op_values,
                    throughput_values
                );

                write_summary_row(summary_out, summary);

                raw_out.flush();
                summary_out.flush();
            }
        }
    }

    std::cout << "\nBenchmark completed.\n";
    std::cout << "Raw CSV:     " << out_path << "\n";
    std::cout << "Summary CSV: " << summary_path << "\n";
    std::cout << "Anti-optimization sink: " << g_bench_sink << "\n";
}