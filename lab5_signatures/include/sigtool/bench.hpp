#pragma once

#include "sigtool/types.hpp"

#include <string>

namespace sigtool {

bool run_benchmark(const BenchConfig& config, std::string& output, std::string& error);

} // namespace sigtool
