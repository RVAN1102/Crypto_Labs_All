#pragma once

#include "encoding.hpp"

#include <map>
#include <string>

std::map<std::string, std::string> parse_options(int argc, char* argv[], int start_index);
std::string require_option(const std::map<std::string, std::string>& opts, const std::string& name);
std::string get_option_or(const std::map<std::string, std::string>& opts, const std::string& name, const std::string& fallback);
void print_usage();
int run_command(int argc, char* argv[]);

Bytes load_label(const std::map<std::string, std::string>& opts);
Bytes load_input_data(const std::map<std::string, std::string>& opts);
