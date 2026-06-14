#include "hashtool/cert.hpp"

#include "hashtool/encoding.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <memory>
#include <sstream>

namespace hashtool {

namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using Asn1StringPtr = std::unique_ptr<ASN1_BIT_STRING, decltype(&ASN1_BIT_STRING_free)>;
using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>;
using ExtendedKeyUsagePtr = std::unique_ptr<EXTENDED_KEY_USAGE, decltype(&EXTENDED_KEY_USAGE_free)>;

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || data == nullptr) {
        return "";
    }
    return std::string(data, static_cast<std::size_t>(len));
}

std::string x509_name_to_string(X509_NAME* name) {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || name == nullptr) {
        return "";
    }
    X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253);
    return bio_to_string(bio.get());
}

std::string asn1_time_to_string(const ASN1_TIME* time) {
    BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || time == nullptr || ASN1_TIME_print(bio.get(), time) != 1) {
        return "";
    }
    return bio_to_string(bio.get());
}

bool load_certificate(const std::string& path, const std::string& format, X509Ptr& cert, std::string& error) {
    const std::string lower_format = lowercase(format.empty() ? "pem" : format);
    if (lower_format != "pem" && lower_format != "der") {
        error = "unsupported certificate format";
        return false;
    }

    BioPtr bio(BIO_new_file(path.c_str(), "rb"), BIO_free);
    if (!bio) {
        error = "cannot open certificate: " + path;
        return false;
    }

    X509* raw = nullptr;
    if (lower_format == "der") {
        raw = d2i_X509_bio(bio.get(), nullptr);
    } else {
        raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    }

    if (raw == nullptr) {
        error = "malformed certificate or unsupported certificate encoding: " + path;
        return false;
    }

    cert.reset(raw);
    return true;
}

std::string object_to_text(const ASN1_OBJECT* obj, bool long_name = true) {
    char buf[256]{};
    const int len = OBJ_obj2txt(buf, sizeof(buf), obj, long_name ? 0 : 1);
    if (len <= 0) {
        return "";
    }
    return std::string(buf, static_cast<std::size_t>(std::min<int>(len, sizeof(buf) - 1)));
}

std::string nid_to_name(int nid) {
    const char* ln = OBJ_nid2ln(nid);
    if (ln != nullptr) {
        return ln;
    }
    const char* sn = OBJ_nid2sn(nid);
    if (sn != nullptr) {
        return sn;
    }
    return "unknown";
}

std::string public_key_algorithm_name(int key_id) {
    switch (key_id) {
    case EVP_PKEY_RSA:
        return "RSA";
    case EVP_PKEY_RSA_PSS:
        return "RSA-PSS";
    case EVP_PKEY_EC:
        return "EC";
    case EVP_PKEY_ED25519:
        return "Ed25519";
    case EVP_PKEY_ED448:
        return "Ed448";
    default:
        return nid_to_name(key_id);
    }
}

std::string public_key_parameters(EVP_PKEY* pkey) {
    if (pkey == nullptr) {
        return "";
    }

    const int key_id = EVP_PKEY_base_id(pkey);
    std::ostringstream out;
    out << "bits=" << EVP_PKEY_bits(pkey);

    if (key_id == EVP_PKEY_EC) {
        char group_name[128]{};
        if (EVP_PKEY_get_utf8_string_param(
                pkey,
                OSSL_PKEY_PARAM_GROUP_NAME,
                group_name,
                sizeof(group_name),
                nullptr) == 1) {
            out << ", curve=" << group_name;
        }
    }

    return out.str();
}

std::vector<std::string> key_usage_names(X509* cert) {
    std::vector<std::string> values;
    Asn1StringPtr usage(
        static_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr)),
        ASN1_BIT_STRING_free);
    if (!usage) {
        return values;
    }

    struct UsageName {
        int bit;
        const char* name;
    };
    const UsageName names[] = {
        {0, "digitalSignature"},
        {1, "nonRepudiation"},
        {2, "keyEncipherment"},
        {3, "dataEncipherment"},
        {4, "keyAgreement"},
        {5, "keyCertSign"},
        {6, "cRLSign"},
        {7, "encipherOnly"},
        {8, "decipherOnly"},
    };

    for (const auto& item : names) {
        if (ASN1_BIT_STRING_get_bit(usage.get(), item.bit) == 1) {
            values.emplace_back(item.name);
        }
    }
    return values;
}

std::vector<std::string> extended_key_usage_names(X509* cert) {
    std::vector<std::string> values;
    ExtendedKeyUsagePtr eku(
        static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr)),
        EXTENDED_KEY_USAGE_free);
    if (!eku) {
        return values;
    }

    const int count = sk_ASN1_OBJECT_num(eku.get());
    for (int i = 0; i < count; ++i) {
        values.push_back(object_to_text(sk_ASN1_OBJECT_value(eku.get(), i)));
    }
    return values;
}

std::vector<std::string> subject_alt_names(X509* cert) {
    std::vector<std::string> values;
    GeneralNamesPtr names(
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)),
        GENERAL_NAMES_free);
    if (!names) {
        return values;
    }

    const int count = sk_GENERAL_NAME_num(names.get());
    for (int i = 0; i < count; ++i) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), i);
        BioPtr bio(BIO_new(BIO_s_mem()), BIO_free);
        if (bio && GENERAL_NAME_print(bio.get(), const_cast<GENERAL_NAME*>(name)) == 1) {
            values.push_back(bio_to_string(bio.get()));
        }
    }
    return values;
}

std::string serial_number_hex(X509* cert) {
    BnPtr bn(ASN1_INTEGER_to_BN(X509_get_serialNumber(cert), nullptr), BN_free);
    if (!bn) {
        return "";
    }
    char* raw = BN_bn2hex(bn.get());
    if (raw == nullptr) {
        return "";
    }
    std::string value(raw);
    OPENSSL_free(raw);
    return value;
}

std::string fingerprint(X509* cert, const EVP_MD* md) {
    unsigned char out[EVP_MAX_MD_SIZE]{};
    unsigned int len = 0;
    if (X509_digest(cert, md, out, &len) != 1) {
        return "";
    }
    return hex_encode(Bytes(out, out + len));
}

std::string join_values(const std::vector<std::string>& values) {
    if (values.empty()) {
        return "(none)";
    }
    std::ostringstream out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << values[i];
    }
    return out.str();
}

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char c : value) {
        switch (c) {
        case '\\':
            out << "\\\\";
            break;
        case '"':
            out << "\\\"";
            break;
        case '\n':
            out << "\\n";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\t':
            out << "\\t";
            break;
        default:
            out << c;
            break;
        }
    }
    return out.str();
}

void json_array(std::ostringstream& out, const std::string& name, const std::vector<std::string>& values, bool comma) {
    out << "  \"" << name << "\": [";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << "\"" << json_escape(values[i]) << "\"";
    }
    out << "]";
    if (comma) {
        out << ",";
    }
    out << "\n";
}

bool time_compare_now(const ASN1_TIME* time, int& day, int& sec) {
    day = 0;
    sec = 0;
    return ASN1_TIME_diff(&day, &sec, nullptr, time) == 1;
}

bool has_tls_server_san(X509* cert) {
    const auto names = subject_alt_names(cert);
    for (const auto& name : names) {
        if (name.rfind("DNS:", 0) == 0 || name.rfind("IP Address:", 0) == 0) {
            return true;
        }
    }
    return false;
}

void add_policy_line(std::ostringstream& out, int& pass, int& warn, int& fail, const std::string& name, const std::string& status, const std::string& detail) {
    out << "CHECK " << name << " " << status << " detail=" << detail << "\n";
    if (status == "PASS") {
        ++pass;
    } else if (status == "WARN") {
        ++warn;
    } else {
        ++fail;
    }
}

} // namespace

bool get_cert_info(const std::string& path, const std::string& format, CertInfo& info, std::string& error) {
    X509Ptr cert(nullptr, X509_free);
    if (!load_certificate(path, format, cert, error)) {
        return false;
    }

    EvpPkeyPtr pkey(X509_get_pubkey(cert.get()), EVP_PKEY_free);
    if (!pkey) {
        error = "certificate does not contain a readable subject public key";
        return false;
    }

    info = CertInfo{};
    info.subject = x509_name_to_string(X509_get_subject_name(cert.get()));
    info.issuer = x509_name_to_string(X509_get_issuer_name(cert.get()));
    info.public_key_algorithm = public_key_algorithm_name(EVP_PKEY_base_id(pkey.get()));
    info.public_key_bits = EVP_PKEY_bits(pkey.get());
    info.public_key_parameters = public_key_parameters(pkey.get());
    info.signature_algorithm = nid_to_name(X509_get_signature_nid(cert.get()));
    info.not_before = asn1_time_to_string(X509_get0_notBefore(cert.get()));
    info.not_after = asn1_time_to_string(X509_get0_notAfter(cert.get()));
    info.key_usage = key_usage_names(cert.get());
    info.extended_key_usage = extended_key_usage_names(cert.get());
    info.subject_alt_names = subject_alt_names(cert.get());
    info.serial_number = serial_number_hex(cert.get());
    info.fingerprint_sha256 = fingerprint(cert.get(), EVP_sha256());
    info.fingerprint_sha1 = fingerprint(cert.get(), EVP_sha1());
    return true;
}

std::string cert_info_to_text(const CertInfo& info) {
    std::ostringstream out;
    out << "subject: " << info.subject << "\n";
    out << "issuer: " << info.issuer << "\n";
    out << "subject_public_key_algorithm: " << info.public_key_algorithm << "\n";
    out << "subject_public_key_parameters: " << info.public_key_parameters << "\n";
    out << "subject_public_key_bits: " << info.public_key_bits << "\n";
    out << "signature_algorithm: " << info.signature_algorithm << "\n";
    out << "not_before: " << info.not_before << "\n";
    out << "not_after: " << info.not_after << "\n";
    out << "key_usage: " << join_values(info.key_usage) << "\n";
    out << "extended_key_usage: " << join_values(info.extended_key_usage) << "\n";
    out << "subject_alt_names: " << join_values(info.subject_alt_names) << "\n";
    out << "serial_number: " << info.serial_number << "\n";
    out << "fingerprint_sha256: " << info.fingerprint_sha256 << "\n";
    out << "fingerprint_sha1_legacy: " << info.fingerprint_sha1 << "\n";
    return out.str();
}

std::string cert_info_to_json(const CertInfo& info) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"subject\": \"" << json_escape(info.subject) << "\",\n";
    out << "  \"issuer\": \"" << json_escape(info.issuer) << "\",\n";
    out << "  \"subject_public_key_algorithm\": \"" << json_escape(info.public_key_algorithm) << "\",\n";
    out << "  \"subject_public_key_parameters\": \"" << json_escape(info.public_key_parameters) << "\",\n";
    out << "  \"subject_public_key_bits\": " << info.public_key_bits << ",\n";
    out << "  \"signature_algorithm\": \"" << json_escape(info.signature_algorithm) << "\",\n";
    out << "  \"not_before\": \"" << json_escape(info.not_before) << "\",\n";
    out << "  \"not_after\": \"" << json_escape(info.not_after) << "\",\n";
    json_array(out, "key_usage", info.key_usage, true);
    json_array(out, "extended_key_usage", info.extended_key_usage, true);
    json_array(out, "subject_alt_names", info.subject_alt_names, true);
    out << "  \"serial_number\": \"" << json_escape(info.serial_number) << "\",\n";
    out << "  \"fingerprint_sha256\": \"" << json_escape(info.fingerprint_sha256) << "\",\n";
    out << "  \"fingerprint_sha1_legacy\": \"" << json_escape(info.fingerprint_sha1) << "\"\n";
    out << "}\n";
    return out.str();
}

bool verify_certificate_signature(
    const std::string& cert_path,
    const std::string& cert_format,
    const std::string& issuer_path,
    const std::string& issuer_format,
    std::string& output,
    std::string& error) {
    X509Ptr cert(nullptr, X509_free);
    X509Ptr issuer(nullptr, X509_free);
    if (!load_certificate(cert_path, cert_format, cert, error) ||
        !load_certificate(issuer_path, issuer_format, issuer, error)) {
        return false;
    }

    EvpPkeyPtr issuer_key(X509_get_pubkey(issuer.get()), EVP_PKEY_free);
    if (!issuer_key) {
        error = "issuer certificate does not contain a readable public key";
        return false;
    }

    const int sig_nid = X509_get_signature_nid(cert.get());
    if (sig_nid == NID_undef) {
        error = "certificate signature algorithm is undefined";
        return false;
    }

    if (X509_verify(cert.get(), issuer_key.get()) != 1) {
        error = "certificate signature verification failed";
        return false;
    }

    int md_nid = NID_undef;
    int pk_nid = NID_undef;
    int secbits = 0;
    unsigned int flags = 0;
    const int has_sig_info = X509_get_signature_info(cert.get(), &md_nid, &pk_nid, &secbits, &flags);

    std::ostringstream out;
    out << "[PASS] certificate signature verified\n";
    out << "signature_algorithm: " << nid_to_name(sig_nid) << "\n";
    out << "signature_algorithm_consistent: " << (has_sig_info == 1 ? "yes" : "unavailable") << "\n";
    output = out.str();
    return true;
}

bool limited_certificate_readability_check(
    const std::string& cert_path,
    const std::string& cert_format,
    std::string& output,
    std::string& error) {
    CertInfo info;
    if (!get_cert_info(cert_path, cert_format, info, error)) {
        return false;
    }
    output = "issuer key unavailable; full signature verification not performed\n"
             "[PASS] certificate parsed; limited validation only\n";
    return true;
}

bool run_certificate_policy(
    const std::string& cert_path,
    const std::string& cert_format,
    std::string& output,
    std::string& error) {
    X509Ptr cert(nullptr, X509_free);
    if (!load_certificate(cert_path, cert_format, cert, error)) {
        return false;
    }

    EvpPkeyPtr pkey(X509_get_pubkey(cert.get()), EVP_PKEY_free);
    if (!pkey) {
        error = "certificate does not contain a readable subject public key";
        return false;
    }

    int pass = 0;
    int warn = 0;
    int fail = 0;
    std::ostringstream out;

    const std::string sig_alg = lowercase(nid_to_name(X509_get_signature_nid(cert.get())));
    add_policy_line(out, pass, warn, fail, "signature_md5", sig_alg.find("md5") == std::string::npos ? "PASS" : "FAIL", sig_alg);
    add_policy_line(out, pass, warn, fail, "signature_sha1", sig_alg.find("sha1") == std::string::npos ? "PASS" : "FAIL", sig_alg);

    const int key_bits = EVP_PKEY_bits(pkey.get());
    if (EVP_PKEY_base_id(pkey.get()) == EVP_PKEY_RSA && key_bits < 2048) {
        add_policy_line(out, pass, warn, fail, "public_key_strength", "WARN", "rsa_bits=" + std::to_string(key_bits));
    } else {
        add_policy_line(out, pass, warn, fail, "public_key_strength", "PASS", "bits=" + std::to_string(key_bits));
    }

    int days = 0;
    int seconds = 0;
    if (!time_compare_now(X509_get0_notBefore(cert.get()), days, seconds)) {
        add_policy_line(out, pass, warn, fail, "validity_not_before", "FAIL", "unreadable");
    } else if (days > 0 || seconds > 0) {
        add_policy_line(out, pass, warn, fail, "validity_not_before", "FAIL", "not_yet_valid");
    } else {
        add_policy_line(out, pass, warn, fail, "validity_not_before", "PASS", "active");
    }

    if (!time_compare_now(X509_get0_notAfter(cert.get()), days, seconds)) {
        add_policy_line(out, pass, warn, fail, "validity_not_after", "FAIL", "unreadable");
    } else if (days < 0 || seconds < 0) {
        add_policy_line(out, pass, warn, fail, "validity_not_after", "FAIL", "expired");
    } else {
        add_policy_line(out, pass, warn, fail, "validity_not_after", "PASS", "not_expired");
    }

    add_policy_line(out, pass, warn, fail, "tls_server_san", has_tls_server_san(cert.get()) ? "PASS" : "FAIL", has_tls_server_san(cert.get()) ? "present" : "missing");
    out << "Policy summary: pass=" << pass << " warn=" << warn << " fail=" << fail << " total=" << (pass + warn + fail) << "\n";
    output = out.str();
    return true;
}

} // namespace hashtool

