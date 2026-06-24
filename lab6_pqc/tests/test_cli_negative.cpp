#include "pqtool/cli.hpp"
#include "pqtool/file_io.hpp"

#include <gtest/gtest.h>

#include <filesystem>

namespace {

int invoke(std::initializer_list<const char*> arguments) {
    std::vector<std::string> storage(arguments.begin(), arguments.end());
    std::vector<char*> pointers;
    for (auto& item : storage) pointers.push_back(item.data());
    return pqtool::run_cli(static_cast<int>(pointers.size()), pointers.data());
}

} // namespace

TEST(Cli, Help) {
    EXPECT_EQ(invoke({"pqtool", "--help"}), 0);
}

TEST(Cli, UnsupportedAlgorithm) {
    EXPECT_THROW(invoke({"pqtool", "keygen", "--algo", "fake", "--pub", "x", "--priv", "y"}), std::exception);
}

TEST(Cli, MissingFile) {
    EXPECT_THROW(invoke({"pqtool", "sign", "--algo", "mldsa-44", "--priv", "missing.pem",
                         "--in", "missing.bin", "--out", "out.sig"}), std::exception);
}

TEST(Cli, MalformedKey) {
    const auto path = std::filesystem::temp_directory_path() / "pqtool-malformed-key.pem";
    pqtool::write_text_atomic(path, "not a key");
    std::vector<std::string> storage{
        "pqtool", "sign", "--algo", "mldsa-44", "--priv", path.string(),
        "--in", path.string(), "--out", "out.sig"};
    std::vector<char*> pointers;
    for (auto& item : storage) pointers.push_back(item.data());
    EXPECT_THROW(
        pqtool::run_cli(static_cast<int>(pointers.size()), pointers.data()),
        std::exception);
    std::filesystem::remove(path);
}
