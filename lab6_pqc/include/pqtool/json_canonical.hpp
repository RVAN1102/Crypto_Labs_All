#pragma once

#include <string>

namespace pqtool {

struct CertificatePayload {
    std::string version;
    std::string subject;
    std::string issuer;
    std::string public_key_algorithm;
    std::string public_key_pem_b64;
    std::string created_utc;
    std::string not_before_utc;
    std::string not_after_utc;
};

std::string json_escape(const std::string& value);
std::string canonical_payload_json(const CertificatePayload& payload);
CertificatePayload parse_canonical_payload(const std::string& json);

} // namespace pqtool

