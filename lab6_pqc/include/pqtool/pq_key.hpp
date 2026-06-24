#pragma once

#include "pqtool/openssl_utils.hpp"

#include <filesystem>
#include <string>

namespace pqtool {

std::string normalize_algorithm(const std::string& cli_name);
bool is_mldsa(const std::string& algorithm);
bool is_mlkem(const std::string& algorithm);
PkeyPtr generate_key(const std::string& algorithm);
PkeyPtr load_private_key(const std::filesystem::path& path, const std::string& expected_algorithm);
PkeyPtr load_public_key(const std::filesystem::path& path, const std::string& expected_algorithm);
void save_private_key(const std::filesystem::path& path, EVP_PKEY* key);
void save_public_key(const std::filesystem::path& path, EVP_PKEY* key);
std::string public_key_pem(EVP_PKEY* key);
PkeyPtr public_key_from_pem(const std::string& pem, const std::string& expected_algorithm);

} // namespace pqtool

