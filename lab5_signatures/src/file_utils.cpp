#include "sigtool/file_utils.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace sigtool {

namespace {

bool ensure_parent_dir(const std::string& path, std::string& error) {
    try {
        const std::filesystem::path p(path);
        const auto parent = p.parent_path();
        if (!parent.empty()) {
            std::filesystem::create_directories(parent);
        }
        return true;
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    }
}

} // namespace

bool read_binary_file(const std::string& path, Bytes& out, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "unable to open input file: " + path;
        return false;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        error = "unable to determine file size: " + path;
        return false;
    }
    in.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(size), 0);
    if (!out.empty() && !in.read(reinterpret_cast<char*>(out.data()), size)) {
        error = "unable to read file: " + path;
        return false;
    }
    return true;
}

bool write_binary_file(const std::string& path, const Bytes& data, std::string& error) {
    if (!ensure_parent_dir(path, error)) {
        return false;
    }
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        error = "unable to open output file: " + path;
        return false;
    }
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    if (!out) {
        error = "unable to write file: " + path;
        return false;
    }
    return true;
}

bool read_text_file(const std::string& path, std::string& out, std::string& error) {
    Bytes bytes;
    if (!read_binary_file(path, bytes, error)) {
        return false;
    }
    out.assign(bytes.begin(), bytes.end());
    return true;
}

bool write_text_file(const std::string& path, const std::string& data, std::string& error) {
    return write_binary_file(path, Bytes(data.begin(), data.end()), error);
}

bool path_exists(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return static_cast<bool>(in);
}

std::string json_escape(const std::string& text) {
    std::ostringstream out;
    for (const unsigned char c : text) {
        switch (c) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u00";
                const char* hex = "0123456789abcdef";
                out << hex[(c >> 4) & 0x0f] << hex[c & 0x0f];
            } else {
                out << static_cast<char>(c);
            }
        }
    }
    return out.str();
}

} // namespace sigtool
