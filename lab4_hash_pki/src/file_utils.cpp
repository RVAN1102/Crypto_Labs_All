#include "hashtool/file_utils.hpp"

#include <fstream>
#include <iterator>

namespace hashtool {

bool read_binary_file(const std::string& path, Bytes& out, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open input file: " + path;
        return false;
    }

    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        error = "failed while reading input file: " + path;
        return false;
    }
    return true;
}

bool write_binary_file(const std::string& path, const Bytes& data, std::string& error) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        error = "cannot open output file: " + path;
        return false;
    }

    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) {
        error = "failed while writing output file: " + path;
        return false;
    }
    return true;
}

bool write_text_file(const std::string& path, const std::string& text, std::string& error) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        error = "cannot open output file: " + path;
        return false;
    }

    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) {
        error = "failed while writing output file: " + path;
        return false;
    }
    return true;
}

} // namespace hashtool

