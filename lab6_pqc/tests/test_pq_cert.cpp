#include "pqtool/pq_cert.hpp"
#include "pqtool/pq_key.hpp"

#include <gtest/gtest.h>

namespace {

struct Fixture {
    pqtool::PkeyPtr ca = pqtool::generate_key("ML-DSA-44");
    pqtool::PkeyPtr subject = pqtool::generate_key("ML-DSA-44");
    pqtool::PqCertificate certificate = pqtool::create_certificate(
        "Student Lab 6", "PQ-CA", subject.get(), "ML-DSA-44", ca.get(), "ML-DSA-44");
};

} // namespace

TEST(PqCert, CreateVerify) {
    Fixture fixture;
    const auto parsed = pqtool::parse_certificate(pqtool::serialize_certificate(fixture.certificate));
    EXPECT_TRUE(pqtool::verify_certificate(parsed, fixture.ca.get()));
}

TEST(PqCert, TamperedSubject) {
    Fixture fixture;
    fixture.certificate.payload.subject = "Mallory";
    EXPECT_FALSE(pqtool::verify_certificate(fixture.certificate, fixture.ca.get()));
}

TEST(PqCert, TamperedPublicKey) {
    Fixture fixture;
    fixture.certificate.payload.public_key_pem_b64[0] ^= 1;
    EXPECT_FALSE(pqtool::verify_certificate(fixture.certificate, fixture.ca.get()));
}

TEST(PqCert, TamperedSignature) {
    Fixture fixture;
    fixture.certificate.signature_b64[0] =
        fixture.certificate.signature_b64[0] == 'A' ? 'B' : 'A';
    EXPECT_FALSE(pqtool::verify_certificate(fixture.certificate, fixture.ca.get()));
}

