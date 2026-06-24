#include "pqtool/json_canonical.hpp"

#include <gtest/gtest.h>

TEST(JsonCanonical, StableOrder) {
    const pqtool::CertificatePayload payload{
        "1", "Student \"Six\"", "PQ-CA", "ML-DSA-44", "QUJD",
        "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"};
    const std::string encoded = pqtool::canonical_payload_json(payload);
    EXPECT_EQ(encoded,
        "{\"version\":\"1\",\"subject\":\"Student \\\"Six\\\"\",\"issuer\":\"PQ-CA\","
        "\"public_key_algorithm\":\"ML-DSA-44\",\"public_key_pem_b64\":\"QUJD\","
        "\"created_utc\":\"2026-01-01T00:00:00Z\",\"not_before_utc\":\"2026-01-01T00:00:00Z\","
        "\"not_after_utc\":\"2027-01-01T00:00:00Z\"}");
    const auto parsed = pqtool::parse_canonical_payload(encoded);
    EXPECT_EQ(parsed.subject, payload.subject);
    EXPECT_THROW(pqtool::parse_canonical_payload(
        "{\"subject\":\"x\",\"version\":\"1\"}"), std::exception);
}

