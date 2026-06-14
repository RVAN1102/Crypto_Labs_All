#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace hashtool {

struct BenchConfig {
    std::string out_path;
    std::string summary_path;
    int runs = 0;
    int ops = 0;
    int warmup_ms = 0;
    std::vector<std::size_t> sizes;
    std::vector<std::string> algos;
    std::string platform;
};

bool run_benchmark(const BenchConfig& config, std::string& output, std::string& error);

} // namespace hashtool

