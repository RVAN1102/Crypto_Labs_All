#pragma once

#include "encoding.hpp"

#include <string>

std::string default_nonce_registry_path();

void check_and_record_nonce_use(
    const std::string& mode,
    const Bytes& key,
    const Bytes& nonce_or_iv,
    const std::string& registry_path
);