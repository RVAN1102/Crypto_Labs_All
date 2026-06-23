#include "sigtool/bench.hpp"

#include "sigtool/file_utils.hpp"
#include "sigtool/signatures.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <sstream>

namespace sigtool {

namespace {

using Clock = std::chrono::steady_clock;

Bytes make_message(std::size_t size) {
    Bytes data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<unsigned char>((i * 131U + 17U) & 0xffU);
    }
    return data;
}

double elapsed_ms(Clock::time_point start, Clock::time_point stop) {
    return std::chrono::duration<double, std::milli>(stop - start).count();
}

std::string size_name(std::size_t size) {
    if (size == 1024ULL) {
        return "1KiB";
    }
    if (size == 16ULL * 1024ULL) {
        return "16KiB";
    }
    if (size == 1024ULL * 1024ULL) {
        return "1MiB";
    }
    if (size == 8ULL * 1024ULL * 1024ULL) {
        return "8MiB";
    }
    return std::to_string(size);
}

struct Stats {
    double mean = 0.0;
    double median = 0.0;
    double stddev = 0.0;
    double ci95 = 0.0;
    double ops_per_sec = 0.0;
};

Stats compute_stats(std::vector<double> values, int ops) {
    Stats stats;
    if (values.empty()) {
        return stats;
    }
    const double sum = std::accumulate(values.begin(), values.end(), 0.0);
    stats.mean = sum / static_cast<double>(values.size());
    std::sort(values.begin(), values.end());
    const std::size_t mid = values.size() / 2;
    stats.median = (values.size() % 2 == 0) ? (values[mid - 1] + values[mid]) / 2.0 : values[mid];
    if (values.size() > 1) {
        double accum = 0.0;
        for (double v : values) {
            accum += (v - stats.mean) * (v - stats.mean);
        }
        stats.stddev = std::sqrt(accum / static_cast<double>(values.size() - 1));
        stats.ci95 = 1.96 * stats.stddev / std::sqrt(static_cast<double>(values.size()));
    }
    stats.ops_per_sec = stats.mean > 0.0 ? (static_cast<double>(ops) * 1000.0 / stats.mean) : 0.0;
    return stats;
}

bool write_summary_row(
    std::ostringstream& summary,
    const std::string& platform,
    Algorithm algorithm,
    const std::string& operation,
    const std::string& size,
    int runs,
    int ops,
    const std::vector<double>& samples) {

    const Stats s = compute_stats(samples, ops);
    summary << platform << ','
            << algorithm_name(algorithm) << ','
            << operation << ','
            << size << ','
            << runs << ','
            << ops << ','
            << std::fixed << std::setprecision(6)
            << s.mean << ','
            << s.median << ','
            << s.stddev << ','
            << s.ci95 << ','
            << s.ops_per_sec << "\n";
    return true;
}

} // namespace

bool run_benchmark(const BenchConfig& config, std::string& output, std::string& error) {
    if (config.algorithms.empty() || config.sizes.empty() || config.runs <= 0 || config.ops <= 0) {
        error = "invalid benchmark configuration";
        return false;
    }

    std::ostringstream raw;
    std::ostringstream summary;
    raw << "platform,algorithm,operation,message_size,run,ops,latency_ms\n";
    summary << "platform,algorithm,operation,message_size,runs,ops,mean_ms,median_ms,stddev_ms,ci95_ms,ops_per_sec\n";

    for (const Algorithm algorithm : config.algorithms) {
        std::vector<double> keygen_samples;
        KeyPair pair;
        for (int run = 1; run <= config.runs; ++run) {
            const auto start = Clock::now();
            for (int op = 0; op < config.ops; ++op) {
                if (!generate_key_pair(algorithm, true, pair, error)) {
                    return false;
                }
            }
            const double ms = elapsed_ms(start, Clock::now());
            keygen_samples.push_back(ms);
            raw << config.platform << ',' << algorithm_name(algorithm) << ",keygen,na,"
                << run << ',' << config.ops << ',' << std::fixed << std::setprecision(6) << ms << "\n";
        }
        write_summary_row(summary, config.platform, algorithm, "keygen", "na", config.runs, config.ops, keygen_samples);

        if (pair.private_key.empty() && !generate_key_pair(algorithm, true, pair, error)) {
            return false;
        }

        for (const std::size_t size : config.sizes) {
            const Bytes message = make_message(size);
            Bytes signature;
            if (!sign_message(algorithm, pair.private_key, message, SignatureEncoding::Der, signature, error)) {
                return false;
            }

            std::vector<double> sign_samples;
            std::vector<double> verify_samples;
            for (int run = 1; run <= config.runs; ++run) {
                const auto sign_start = Clock::now();
                for (int op = 0; op < config.ops; ++op) {
                    if (!sign_message(algorithm, pair.private_key, message, SignatureEncoding::Der, signature, error)) {
                        return false;
                    }
                }
                const double sign_ms = elapsed_ms(sign_start, Clock::now());
                sign_samples.push_back(sign_ms);
                raw << config.platform << ',' << algorithm_name(algorithm) << ",sign," << size_name(size) << ','
                    << run << ',' << config.ops << ',' << std::fixed << std::setprecision(6) << sign_ms << "\n";

                const auto verify_start = Clock::now();
                for (int op = 0; op < config.ops; ++op) {
                    VerifyResult result;
                    if (!verify_message(algorithm, pair.public_key, message, signature, SignatureEncoding::Der, result, error)) {
                        return false;
                    }
                    if (!result.ok) {
                        error = "benchmark verification failed";
                        return false;
                    }
                }
                const double verify_ms = elapsed_ms(verify_start, Clock::now());
                verify_samples.push_back(verify_ms);
                raw << config.platform << ',' << algorithm_name(algorithm) << ",verify," << size_name(size) << ','
                    << run << ',' << config.ops << ',' << std::fixed << std::setprecision(6) << verify_ms << "\n";
            }

            write_summary_row(summary, config.platform, algorithm, "sign", size_name(size), config.runs, config.ops, sign_samples);
            write_summary_row(summary, config.platform, algorithm, "verify", size_name(size), config.runs, config.ops, verify_samples);
        }
    }

    if (!write_text_file(config.out_path, raw.str(), error) ||
        !write_text_file(config.summary_path, summary.str(), error)) {
        return false;
    }

    output = "Benchmark complete\nRaw CSV: " + config.out_path + "\nSummary CSV: " + config.summary_path + "\n";
    return true;
}

} // namespace sigtool
