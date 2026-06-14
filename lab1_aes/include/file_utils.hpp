#pragma once

#include "encoding.hpp"

#include <string>

Bytes read_file_binary(const std::string& path);
std::string read_text_file(const std::string& path);

void write_file_binary(const std::string& path, const Bytes& data);
void write_text_file(const std::string& path, const std::string& text);