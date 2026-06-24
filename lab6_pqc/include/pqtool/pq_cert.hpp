#pragma once

#include "pqtool/json_canonical.hpp"
#include "pqtool/openssl_utils.hpp"

#include <string>

namespace pqtool {

struct PqCertificate {
    CertificatePayload payload;
    std::string signature_algorithm;
    std::string signature_b64;
};

PqCertificate create_certificate(
    const std::string& subject,
    const std::string& issuer,
    EVP_PKEY* subject_public_key,
    const std::string& subject_algorithm,
    EVP_PKEY* ca_private_key,
    const std::string& signature_algorithm);
bool verify_certificate(const PqCertificate& certificate, EVP_PKEY* ca_public_key);
std::string serialize_certificate(const PqCertificate& certificate);
PqCertificate parse_certificate(const std::string& json);

} // namespace pqtool

