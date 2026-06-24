#include "pqtool/pq_cert.hpp"

#include "pqtool/encoding.hpp"
#include "pqtool/errors.hpp"
#include "pqtool/mldsa.hpp"
#include "pqtool/pq_key.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace pqtool {
namespace {

std::string utc_time(std::chrono::system_clock::time_point value) {
    const std::time_t raw = std::chrono::system_clock::to_time_t(value);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &raw);
#else
    gmtime_r(&raw, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::string extract_object(const std::string& input, std::size_t start, std::size_t& end) {
    if (start >= input.size() || input[start] != '{') {
        fail("Malformed certificate JSON.");
    }
    bool in_string = false;
    bool escaped = false;
    int depth = 0;
    for (std::size_t i = start; i < input.size(); ++i) {
        const char c = input[i];
        if (in_string) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') in_string = true;
        else if (c == '{') ++depth;
        else if (c == '}' && --depth == 0) {
            end = i + 1;
            return input.substr(start, end - start);
        }
    }
    fail("Malformed certificate JSON.");
}

std::string parse_json_string_at(const std::string& input, std::size_t& position) {
    if (position >= input.size() || input[position++] != '"') {
        fail("Malformed certificate JSON.");
    }
    std::string encoded;
    while (position < input.size()) {
        const char c = input[position++];
        if (c == '"') {
            return parse_canonical_payload(
                "{\"version\":\"1\",\"subject\":\"" + encoded +
                "\",\"issuer\":\"\",\"public_key_algorithm\":\"\",\"public_key_pem_b64\":\"\","
                "\"created_utc\":\"\",\"not_before_utc\":\"\",\"not_after_utc\":\"\"}").subject;
        }
        if (c == '\\') {
            if (position >= input.size()) fail("Malformed certificate JSON.");
            encoded.push_back(c);
            encoded.push_back(input[position++]);
        } else {
            encoded.push_back(c);
        }
    }
    fail("Malformed certificate JSON.");
}

} // namespace

PqCertificate create_certificate(
    const std::string& subject,
    const std::string& issuer,
    EVP_PKEY* subject_public_key,
    const std::string& subject_algorithm,
    EVP_PKEY* ca_private_key,
    const std::string& signature_algorithm) {
    if (!is_mldsa(subject_algorithm) || !is_mldsa(signature_algorithm)) {
        fail("Certificates require ML-DSA subject and issuer keys.");
    }
    if (EVP_PKEY_is_a(subject_public_key, subject_algorithm.c_str()) != 1 ||
        EVP_PKEY_is_a(ca_private_key, signature_algorithm.c_str()) != 1) {
        fail("Certificate key algorithm mismatch.");
    }
    const auto now = std::chrono::system_clock::now();
    const std::string subject_pem = public_key_pem(subject_public_key);
    const Bytes subject_pem_bytes(subject_pem.begin(), subject_pem.end());
    PqCertificate certificate;
    certificate.payload = {
        "1",
        subject,
        issuer,
        subject_algorithm,
        base64_encode(subject_pem_bytes),
        utc_time(now),
        utc_time(now),
        utc_time(now + std::chrono::hours(24 * 365)),
    };
    const std::string canonical = canonical_payload_json(certificate.payload);
    const Bytes message(canonical.begin(), canonical.end());
    certificate.signature_algorithm = signature_algorithm;
    certificate.signature_b64 = base64_encode(mldsa_sign(ca_private_key, message));
    return certificate;
}

bool verify_certificate(const PqCertificate& certificate, EVP_PKEY* ca_public_key) {
    if (certificate.payload.version != "1" ||
        !is_mldsa(certificate.payload.public_key_algorithm) ||
        !is_mldsa(certificate.signature_algorithm) ||
        EVP_PKEY_is_a(ca_public_key, certificate.signature_algorithm.c_str()) != 1) {
        return false;
    }
    try {
        const Bytes public_pem = base64_decode(certificate.payload.public_key_pem_b64);
        const std::string pem(public_pem.begin(), public_pem.end());
        (void)public_key_from_pem(pem, certificate.payload.public_key_algorithm);
        const Bytes signature = base64_decode(certificate.signature_b64);
        const std::string canonical = canonical_payload_json(certificate.payload);
        const Bytes message(canonical.begin(), canonical.end());
        return mldsa_verify(ca_public_key, message, signature);
    } catch (...) {
        return false;
    }
}

std::string serialize_certificate(const PqCertificate& certificate) {
    return "{\"payload\":" + canonical_payload_json(certificate.payload) +
        ",\"signature_algorithm\":\"" + json_escape(certificate.signature_algorithm) +
        "\",\"signature_b64\":\"" + json_escape(certificate.signature_b64) + "\"}\n";
}

PqCertificate parse_certificate(const std::string& json) {
    const std::string prefix = "{\"payload\":";
    if (json.rfind(prefix, 0) != 0) {
        fail("Malformed certificate JSON.");
    }
    std::size_t position = prefix.size();
    std::size_t payload_end = 0;
    const std::string payload_json = extract_object(json, position, payload_end);
    position = payload_end;
    const std::string signature_prefix = ",\"signature_algorithm\":";
    if (json.compare(position, signature_prefix.size(), signature_prefix) != 0) {
        fail("Malformed certificate JSON.");
    }
    position += signature_prefix.size();
    const std::string signature_algorithm = parse_json_string_at(json, position);
    const std::string value_prefix = ",\"signature_b64\":";
    if (json.compare(position, value_prefix.size(), value_prefix) != 0) {
        fail("Malformed certificate JSON.");
    }
    position += value_prefix.size();
    const std::string signature_b64 = parse_json_string_at(json, position);
    if (position >= json.size() || json[position++] != '}') {
        fail("Malformed certificate JSON.");
    }
    while (position < json.size() &&
           (json[position] == '\n' || json[position] == '\r' ||
            json[position] == ' ' || json[position] == '\t')) {
        ++position;
    }
    if (position != json.size()) {
        fail("Unexpected certificate JSON content.");
    }
    PqCertificate certificate{parse_canonical_payload(payload_json), signature_algorithm, signature_b64};
    (void)base64_decode(certificate.signature_b64);
    (void)base64_decode(certificate.payload.public_key_pem_b64);
    return certificate;
}

} // namespace pqtool
