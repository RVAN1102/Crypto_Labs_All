#include "file_utils.hpp"

#include <fstream>
#include <stdexcept>

Bytes read_file_binary(const std::string& path) {
    std::ifstream in(path, std::ios::binary);

    if (!in) {
        throw std::runtime_error("Cannot open input file: " + path);
    }

    in.seekg(0, std::ios::end);
    std::streamoff size = in.tellg();

    if (size < 0) {
        throw std::runtime_error("Cannot determine file size: " + path);
    }

    in.seekg(0, std::ios::beg);

    Bytes data(static_cast<size_t>(size));

    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));

        if (!in) {
            throw std::runtime_error("Failed to read file: " + path);
        }
    }

    return data;
}

std::string read_text_file(const std::string& path) {
    Bytes data = read_file_binary(path);
    return std::string(data.begin(), data.end());
}

void write_file_binary(const std::string& path, const Bytes& data) {
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        throw std::runtime_error("Cannot open output file: " + path);
    }

    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));

        if (!out) {
            throw std::runtime_error("Failed to write file: " + path);
        }
    }
}

void write_text_file(const std::string& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        throw std::runtime_error("Cannot open output file: " + path);
    }

    out.write(text.data(), static_cast<std::streamsize>(text.size()));

    if (!out) {
        throw std::runtime_error("Failed to write file: " + path);
    }
}