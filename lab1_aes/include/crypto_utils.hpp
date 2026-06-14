#pragma once

#include "encoding.hpp"

#include <map>
#include <string>


Bytes random_bytes(size_t n);

void validate_aes_key(const Bytes& key);
void validate_xts_key(const Bytes& key);

Bytes load_key(const std::map<std::string, std::string>& opts);
Bytes load_xts_key(const std::map<std::string, std::string>& opts);
Bytes load_input_data(const std::map<std::string, std::string>& opts);
Bytes load_aad(const std::map<std::string, std::string>& opts);

Bytes load_or_generate_gcm_nonce(const std::map<std::string, std::string>& opts);
Bytes load_or_generate_aes_iv(const std::map<std::string, std::string>& opts);
Bytes load_or_generate_ccm_nonce(const std::map<std::string, std::string>& opts);