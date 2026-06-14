#include "hashtool/bench.hpp"

#include "hashtool/hash.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <sstream>

namespace hashtool {

namespace {

struct RawRow {
    std::string platform;
    std::string algo;
    std::size_t input_size_bytes = 0;
    std::string mode = "hash";
    int run = 0;
    int ops = 0;
    int warmup_ms = 0;
    double total_ms = 0.0;
    double latency_ms_per_op = 0.0;
    double throughput_mib_s = 0.0;
    std::size_t digest_size_bytes = 0;
    bool streaming = true;
    std::string compiler;
    std::string build_type;
};

std::string compiler_string() {
#if defined(__clang__)
    return "clang-" + std::to_string(__clang_major__) + "." + std::to_string(__clang_minor__);
#elif defined(__GNUC__)
    return "gcc-" + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__);
#elif defined(_MSC_VER)
    return "msvc-" + std::to_string(_MSC_VER);
#else
    return "unknown";
#endif
}

std::string build_type_string() {
#ifdef HASHTOOL_BUILD_TYPE
    return HASHTOOL_BUILD_TYPE;
#else
    return "unspecified";
#endif
}

std::filesystem::path benchmark_temp_dir() {
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::path("tmp_benchmark") / ("bench_" + std::to_string(ticks));
}

bool ensure_parent_directory(const std::string& path, std::string& error) {
    const std::filesystem::path p(path);
    const auto parent = p.parent_path();
    if (parent.empty()) {
        return true;
    }
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        error = "cannot create output directory: " + parent.string();
        return false;
    }
    return true;
}

bool write_synthetic_file(const std::filesystem::path& path, std::size_t size, std::string& error) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        error = "cannot create benchmark input: " + path.string();
        return false;
    }

    constexpr std::size_t chunk_size = 1024 * 1024;
    std::vector<char> chunk(chunk_size);
    std::uint64_t offset = 0;
    std::size_t remaining = size;
    while (remaining > 0) {
        const std::size_t n = std::min<std::size_t>(chunk.size(), remaining);
        for (std::size_t i = 0; i < n; ++i) {
            chunk[i] = static_cast<char>((offset + i * 131u + 17u) & 0xffu);
        }
        out.write(chunk.data(), static_cast<std::streamsize>(n));
        if (!out) {
            error = "failed while writing benchmark input: " + path.string();
            return false;
        }
        offset += n;
        remaining -= n;
    }

    return true;
}

bool parse_algorithm(const std::string& value, HashAlgorithm& algorithm) {
    return (value == "sha256" || value == "sha512" || value == "sha3-256" || value == "sha3-512") &&
        parse_hash_algorithm(value, algorithm);
}

double mean(const std::vector<double>& values) {
    if (values.empty()) {
        return 0.0;
    }
    return std::accumulate(values.begin(), values.end(), 0.0) / static_cast<double>(values.size());
}

double median(std::vector<double> values) {
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end());
    const std::size_t mid = values.size() / 2;
    if ((values.size() % 2) == 0) {
        return (values[mid - 1] + values[mid]) / 2.0;
    }
    return values[mid];
}

double sample_stddev(const std::vector<double>& values) {
    if (values.size() <= 1) {
        return 0.0;
    }
    const double avg = mean(values);
    double sum = 0.0;
    for (const double value : values) {
        const double diff = value - avg;
        sum += diff * diff;
    }
    return std::sqrt(sum / static_cast<double>(values.size() - 1));
}

double ci95(const std::vector<double>& values) {
    if (values.size() <= 1) {
        return 0.0;
    }
    return 1.96 * sample_stddev(values) / std::sqrt(static_cast<double>(values.size()));
}

void write_raw_header(std::ofstream& out) {
    out << "platform,algo,input_size_bytes,mode,run,ops,warmup_ms,total_ms,latency_ms_per_op,throughput_mib_s,digest_size_bytes,streaming,compiler,build_type\n";
}

void write_summary_header(std::ofstream& out) {
    out << "platform,algo,input_size_bytes,mode,runs,ops_per_run,mean_mib_s,median_mib_s,stddev_mib_s,ci95_mib_s,mean_latency_ms,median_latency_ms,stddev_latency_ms,ci95_latency_ms\n";
}

void write_raw_row(std::ofstream& out, const RawRow& row) {
    out << row.platform << ','
        << row.algo << ','
        << row.input_size_bytes << ','
        << row.mode << ','
        << row.run << ','
        << row.ops << ','
        << row.warmup_ms << ','
        << std::fixed << std::setprecision(6)
        << row.total_ms << ','
        << row.latency_ms_per_op << ','
        << row.throughput_mib_s << ','
        << row.digest_size_bytes << ','
        << (row.streaming ? "true" : "false") << ','
        << row.compiler << ','
        << row.build_type << '\n';
}

void write_summary_row(std::ofstream& out, const std::vector<RawRow>& rows) {
    std::vector<double> throughputs;
    std::vector<double> latencies;
    throughputs.reserve(rows.size());
    latencies.reserve(rows.size());
    for (const auto& row : rows) {
        throughputs.push_back(row.throughput_mib_s);
        latencies.push_back(row.latency_ms_per_op);
    }

    const auto& first = rows.front();
    out << first.platform << ','
        << first.algo << ','
        << first.input_size_bytes << ','
        << first.mode << ','
        << rows.size() << ','
        << first.ops << ','
        << std::fixed << std::setprecision(6)
        << mean(throughputs) << ','
        << median(throughputs) << ','
        << sample_stddev(throughputs) << ','
        << ci95(throughputs) << ','
        << mean(latencies) << ','
        << median(latencies) << ','
        << sample_stddev(latencies) << ','
        << ci95(latencies) << '\n';
}

bool validate_config(const BenchConfig& config, std::string& error) {
    if (config.out_path.empty()) {
        error = "missing --out";
        return false;
    }
    if (config.summary_path.empty()) {
        error = "missing --summary";
        return false;
    }
    if (config.runs <= 0) {
        error = "invalid --runs";
        return false;
    }
    if (config.ops <= 0) {
        error = "invalid --ops";
        return false;
    }
    if (config.warmup_ms < 0) {
        error = "invalid --warmup-ms";
        return false;
    }
    if (config.algos.empty()) {
        error = "empty --algos";
        return false;
    }
    if (config.sizes.empty()) {
        error = "empty --sizes";
        return false;
    }
    if (config.platform.empty()) {
        error = "missing --platform";
        return false;
    }

    for (const auto& algo : config.algos) {
        HashAlgorithm parsed;
        if (!parse_algorithm(algo, parsed)) {
            error = "unsupported benchmark algorithm: " + algo;
            return false;
        }
    }
    return true;
}

} // namespace

bool run_benchmark(const BenchConfig& config, std::string& output, std::string& error) {
    if (!validate_config(config, error)) {
        return false;
    }
    if (!ensure_parent_directory(config.out_path, error) ||
        !ensure_parent_directory(config.summary_path, error)) {
        return false;
    }

    const auto temp_dir = benchmark_temp_dir();
    std::error_code ec;
    std::filesystem::create_directories(temp_dir, ec);
    if (ec) {
        error = "cannot create temporary benchmark directory";
        return false;
    }

    struct TempCleanup {
        std::filesystem::path path;
        ~TempCleanup() {
            std::error_code cleanup_ec;
            std::filesystem::remove_all(path, cleanup_ec);
        }
    } cleanup{temp_dir};

    std::ofstream raw(config.out_path, std::ios::binary);
    if (!raw) {
        error = "cannot open raw benchmark CSV";
        return false;
    }
    std::ofstream summary(config.summary_path, std::ios::binary);
    if (!summary) {
        error = "cannot open summary benchmark CSV";
        return false;
    }

    write_raw_header(raw);
    write_summary_header(summary);

    std::size_t total_rows = 0;
    const std::string compiler = compiler_string();
    const std::string build_type = build_type_string();

    for (const auto size : config.sizes) {
        const auto input_path = temp_dir / ("input_" + std::to_string(size) + ".bin");
        if (!write_synthetic_file(input_path, size, error)) {
            return false;
        }

        for (const auto& algo : config.algos) {
            HashAlgorithm algorithm;
            if (!parse_algorithm(algo, algorithm)) {
                error = "unsupported benchmark algorithm: " + algo;
                return false;
            }

            Bytes digest;
            const auto warmup_end = std::chrono::steady_clock::now() + std::chrono::milliseconds(config.warmup_ms);
            do {
                if (!hash_file_streaming(algorithm, input_path.string(), 0, digest, error)) {
                    return false;
                }
            } while (config.warmup_ms > 0 && std::chrono::steady_clock::now() < warmup_end);

            std::vector<RawRow> rows_for_summary;
            for (int run = 1; run <= config.runs; ++run) {
                const auto start = std::chrono::steady_clock::now();
                for (int op = 0; op < config.ops; ++op) {
                    if (!hash_file_streaming(algorithm, input_path.string(), 0, digest, error)) {
                        return false;
                    }
                }
                const auto stop = std::chrono::steady_clock::now();
                const double total_ms = std::chrono::duration<double, std::milli>(stop - start).count();
                const double latency = total_ms / static_cast<double>(config.ops);
                const double mib = (static_cast<double>(size) * static_cast<double>(config.ops)) / (1024.0 * 1024.0);
                const double throughput = total_ms > 0.0 ? mib / (total_ms / 1000.0) : 0.0;

                RawRow row;
                row.platform = config.platform;
                row.algo = algo;
                row.input_size_bytes = size;
                row.run = run;
                row.ops = config.ops;
                row.warmup_ms = config.warmup_ms;
                row.total_ms = total_ms;
                row.latency_ms_per_op = latency;
                row.throughput_mib_s = throughput;
                row.digest_size_bytes = digest.size();
                row.compiler = compiler;
                row.build_type = build_type;
                write_raw_row(raw, row);
                rows_for_summary.push_back(row);
                ++total_rows;
            }
            write_summary_row(summary, rows_for_summary);
        }
    }

    output = "Benchmark complete: raw=" + config.out_path +
        " summary=" + config.summary_path +
        " rows=" + std::to_string(total_rows) + "\n";
    return true;
}

} // namespace hashtool
