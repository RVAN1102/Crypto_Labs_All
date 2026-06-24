#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace pqtool {

void run_benchmark(
    const std::string& algorithm,
    const std::vector<std::string>& operations,
    const std::vector<std::size_t>& sizes,
    int runs,
    const std::filesystem::path& output);
void run_timing_variance(
    const std::string& algorithm,
    const std::string& test_case,
    int runs,
    const std::filesystem::path& output);

} // namespace pqtool

