#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace sigtool {

using Bytes = std::vector<unsigned char>;

enum class Algorithm {
    EcdsaP256,
    RsaPss3072
};

enum class SignatureEncoding {
    Raw,
    Der,
    Base64
};

struct KeyPair {
    Bytes private_key;
    Bytes public_key;
};

struct VerifyResult {
    bool ok = false;
    std::string detail;
};

struct BenchConfig {
    std::string out_path;
    std::string summary_path;
    std::vector<Algorithm> algorithms;
    std::vector<std::size_t> sizes;
    int runs = 30;
    int ops = 1;
    std::string platform = "unknown";
};

} // namespace sigtool
