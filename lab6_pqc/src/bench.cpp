#include "pqtool/bench.hpp"

#include "pqtool/errors.hpp"
#include "pqtool/file_io.hpp"
#include "pqtool/mldsa.hpp"
#include "pqtool/mlkem.hpp"
#include "pqtool/openssl_utils.hpp"
#include "pqtool/pq_key.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <sstream>

namespace pqtool {
namespace {

using Clock = std::chrono::steady_clock;

double elapsed_ms(const Clock::time_point& start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

bool contains(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

std::filesystem::path summary_path(const std::filesystem::path& raw) {
    return raw.parent_path() / (raw.stem().string() + "_summary.csv");
}

struct Sample {
    std::string operation;
    std::size_t size;
    int run;
    double milliseconds;
    bool success;
};

void append_sample(
    std::vector<Sample>& samples,
    const std::string& operation,
    std::size_t size,
    int run,
    const Clock::time_point& start,
    bool success) {
    samples.push_back({operation, size, run, elapsed_ms(start), success});
}

} // namespace

void run_benchmark(
    const std::string& algorithm,
    const std::vector<std::string>& operations,
    const std::vector<std::size_t>& requested_sizes,
    int runs,
    const std::filesystem::path& output) {
    if (runs <= 0) {
        fail("Benchmark runs must be positive.");
    }
    const bool dsa = is_mldsa(algorithm);
    const bool kem = is_mlkem(algorithm);
    if (!dsa && !kem) {
        fail("Unsupported benchmark algorithm.");
    }
    const std::vector<std::size_t> sizes =
        dsa ? requested_sizes : std::vector<std::size_t>{0};
    if (sizes.empty()) {
        fail("ML-DSA benchmark requires at least one message size.");
    }

    PkeyPtr key = generate_key(algorithm);
    std::vector<Sample> samples;
    for (int run = 1; run <= runs; ++run) {
        if (contains(operations, "keygen")) {
            const auto start = Clock::now();
            PkeyPtr generated = generate_key(algorithm);
            append_sample(samples, "keygen", 0, run, start, generated != nullptr);
        }
        if (dsa) {
            for (const std::size_t size : sizes) {
                Bytes message(size, static_cast<std::uint8_t>(run));
                Bytes signature;
                if (contains(operations, "sign")) {
                    const auto start = Clock::now();
                    signature = mldsa_sign(key.get(), message);
                    append_sample(samples, "sign", size, run, start, !signature.empty());
                } else {
                    signature = mldsa_sign(key.get(), message);
                }
                if (contains(operations, "verify")) {
                    const auto start = Clock::now();
                    const bool valid = mldsa_verify(key.get(), message, signature);
                    append_sample(samples, "verify", size, run, start, valid);
                }
            }
        } else {
            Encapsulation encapsulation = mlkem_encapsulate(key.get());
            if (contains(operations, "encaps")) {
                const auto start = Clock::now();
                Encapsulation measured = mlkem_encapsulate(key.get());
                append_sample(samples, "encaps", 0, run, start, !measured.shared_secret.empty());
                cleanse(measured.shared_secret.data(), measured.shared_secret.size());
            }
            if (contains(operations, "decaps")) {
                const auto start = Clock::now();
                Bytes secret = mlkem_decapsulate(key.get(), encapsulation.ciphertext);
                const bool valid = secret == encapsulation.shared_secret;
                append_sample(samples, "decaps", 0, run, start, valid);
                cleanse(secret.data(), secret.size());
            }
            cleanse(encapsulation.shared_secret.data(), encapsulation.shared_secret.size());
        }
    }

    std::ostringstream raw;
    raw << "algorithm,operation,message_size_bytes,run_index,latency_ms,success\n";
    raw << std::fixed << std::setprecision(6);
    for (const auto& sample : samples) {
        raw << algorithm << ',' << sample.operation << ',' << sample.size << ','
            << sample.run << ',' << sample.milliseconds << ','
            << (sample.success ? "true" : "false") << '\n';
    }
    write_text_atomic(output, raw.str());

    std::ostringstream summary;
    summary << "algorithm,operation,message_size_bytes,runs,mean_ms,median_ms,stddev_ms,ci95_ms,ops_per_sec\n";
    summary << std::fixed << std::setprecision(6);
    for (const auto& operation : operations) {
        std::vector<std::size_t> operation_sizes =
            operation == "keygen" || kem ? std::vector<std::size_t>{0} : sizes;
        for (const auto size : operation_sizes) {
            std::vector<double> values;
            for (const auto& sample : samples) {
                if (sample.operation == operation && sample.size == size && sample.success) {
                    values.push_back(sample.milliseconds);
                }
            }
            if (values.empty()) continue;
            const double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
            std::sort(values.begin(), values.end());
            const double median = values.size() % 2 == 0
                ? (values[values.size() / 2 - 1] + values[values.size() / 2]) / 2.0
                : values[values.size() / 2];
            double sum_squares = 0.0;
            for (const double value : values) {
                sum_squares += (value - mean) * (value - mean);
            }
            const double stddev = values.size() > 1
                ? std::sqrt(sum_squares / static_cast<double>(values.size() - 1))
                : 0.0;
            const double ci95 = 1.96 * stddev / std::sqrt(static_cast<double>(values.size()));
            const double ops_per_second = mean > 0.0 ? 1000.0 / mean : 0.0;
            summary << algorithm << ',' << operation << ',' << size << ','
                    << values.size() << ',' << mean << ',' << median << ','
                    << stddev << ',' << ci95 << ',' << ops_per_second << '\n';
        }
    }
    write_text_atomic(summary_path(output), summary.str());
}

void run_timing_variance(
    const std::string& algorithm,
    const std::string& test_case,
    int runs,
    const std::filesystem::path& output) {
    if (runs <= 0) fail("Timing runs must be positive.");
    PkeyPtr key = generate_key(algorithm);
    std::ostringstream csv;
    csv << "algorithm,case,variant,run_index,latency_ms,success\n";
    csv << std::fixed << std::setprecision(6);

    if (is_mldsa(algorithm) && test_case == "verify-valid-vs-invalid") {
        const Bytes message(1024, 0x42);
        const Bytes signature = mldsa_sign(key.get(), message);
        Bytes invalid = signature;
        invalid[0] ^= 1;
        for (int run = 1; run <= runs; ++run) {
            for (const auto& item : {std::pair<const char*, const Bytes*>{"valid", &signature},
                                     {"invalid", &invalid}}) {
                const auto start = Clock::now();
                const bool result = mldsa_verify(key.get(), message, *item.second);
                csv << algorithm << ',' << test_case << ',' << item.first << ',' << run
                    << ',' << elapsed_ms(start) << ',' << (result ? "true" : "false") << '\n';
            }
        }
    } else if (is_mlkem(algorithm) && test_case == "decaps-valid-vs-invalid") {
        Encapsulation encapsulation = mlkem_encapsulate(key.get());
        Bytes invalid = encapsulation.ciphertext;
        invalid[0] ^= 1;
        for (int run = 1; run <= runs; ++run) {
            for (const auto& item : {std::pair<const char*, const Bytes*>{"valid", &encapsulation.ciphertext},
                                     {"invalid", &invalid}}) {
                const auto start = Clock::now();
                Bytes secret = mlkem_decapsulate(key.get(), *item.second);
                const bool matches = secret == encapsulation.shared_secret;
                csv << algorithm << ',' << test_case << ',' << item.first << ',' << run
                    << ',' << elapsed_ms(start) << ',' << (matches ? "true" : "false") << '\n';
                cleanse(secret.data(), secret.size());
            }
        }
        cleanse(encapsulation.shared_secret.data(), encapsulation.shared_secret.size());
    } else {
        fail("Unsupported timing-variance case for algorithm.");
    }
    write_text_atomic(output, csv.str());
}

} // namespace pqtool

