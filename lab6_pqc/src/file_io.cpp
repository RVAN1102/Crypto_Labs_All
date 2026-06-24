#include "pqtool/file_io.hpp"

#include "pqtool/errors.hpp"

#include <chrono>
#include <fstream>
#include <sstream>
#include <system_error>

namespace pqtool {
namespace {

std::filesystem::path temporary_path(const std::filesystem::path& path) {
    const auto tick = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return path.parent_path() / (path.filename().string() + ".tmp." + std::to_string(tick));
}

void ensure_parent(const std::filesystem::path& path) {
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            fail("Cannot create output directory: " + parent.string());
        }
    }
}

template <typename Writer>
void atomic_write(const std::filesystem::path& path, Writer writer) {
    ensure_parent(path);
    const auto temp = temporary_path(path);
    try {
        writer(temp);
        std::error_code ec;
#if defined(_WIN32)
        std::filesystem::remove(path, ec);
        ec.clear();
#endif
        std::filesystem::rename(temp, path, ec);
        if (ec) {
            std::filesystem::remove(temp);
            fail("Cannot finalize output file: " + path.string());
        }
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temp, ignored);
        throw;
    }
}

} // namespace

Bytes read_binary(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        fail("Cannot open input file: " + path.string());
    }
    input.seekg(0, std::ios::end);
    const auto length = input.tellg();
    if (length < 0) {
        fail("Cannot determine input size: " + path.string());
    }
    input.seekg(0, std::ios::beg);
    Bytes data(static_cast<std::size_t>(length));
    if (!data.empty() && !input.read(reinterpret_cast<char*>(data.data()), length)) {
        fail("Cannot read input file: " + path.string());
    }
    return data;
}

std::string read_text(const std::filesystem::path& path) {
    const Bytes data = read_binary(path);
    return {data.begin(), data.end()};
}

void write_binary_atomic(const std::filesystem::path& path, const Bytes& data) {
    atomic_write(path, [&](const std::filesystem::path& temp) {
        std::ofstream output(temp, std::ios::binary | std::ios::trunc);
        if (!output || (!data.empty() && !output.write(
                reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size())))) {
            fail("Cannot write output file: " + path.string());
        }
    });
}

void write_text_atomic(const std::filesystem::path& path, const std::string& data) {
    const Bytes bytes(data.begin(), data.end());
    write_binary_atomic(path, bytes);
}

} // namespace pqtool

