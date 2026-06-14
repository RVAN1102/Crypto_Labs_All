#pragma once

#include <map>
#include <string>

std::map<std::string, std::string> parse_options(int argc, char* argv[], int start_index);

std::string require_option(
    const std::map<std::string, std::string>& opts,
    const std::string& name
);

void print_usage();