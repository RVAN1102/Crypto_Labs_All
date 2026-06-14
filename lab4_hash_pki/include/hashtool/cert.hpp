#pragma once

#include <string>
#include <vector>

namespace hashtool {

struct CertInfo {
    std::string subject;
    std::string issuer;
    std::string public_key_algorithm;
    std::string public_key_parameters;
    int public_key_bits = 0;
    std::string signature_algorithm;
    std::string not_before;
    std::string not_after;
    std::vector<std::string> key_usage;
    std::vector<std::string> extended_key_usage;
    std::vector<std::string> subject_alt_names;
    std::string serial_number;
    std::string fingerprint_sha256;
    std::string fingerprint_sha1;
};

bool get_cert_info(const std::string& path, const std::string& format, CertInfo& info, std::string& error);
std::string cert_info_to_text(const CertInfo& info);
std::string cert_info_to_json(const CertInfo& info);

bool verify_certificate_signature(
    const std::string& cert_path,
    const std::string& cert_format,
    const std::string& issuer_path,
    const std::string& issuer_format,
    std::string& output,
    std::string& error);

bool limited_certificate_readability_check(
    const std::string& cert_path,
    const std::string& cert_format,
    std::string& output,
    std::string& error);

bool run_certificate_policy(
    const std::string& cert_path,
    const std::string& cert_format,
    std::string& output,
    std::string& error);

} // namespace hashtool

