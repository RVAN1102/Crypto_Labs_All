#include "pqtool/json_canonical.hpp"

#include "pqtool/errors.hpp"

#include <array>
#include <cctype>
#include <map>
#include <sstream>

namespace pqtool {
namespace {

class Parser {
public:
    explicit Parser(const std::string& input) : input_(input) {}

    void whitespace() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\n' ||
                input_[position_] == '\r' || input_[position_] == '\t')) {
            ++position_;
        }
    }

    void expect(char value) {
        whitespace();
        if (position_ >= input_.size() || input_[position_] != value) {
            fail("Malformed certificate JSON.");
        }
        ++position_;
    }

    std::string string() {
        whitespace();
        expect_raw('"');
        std::string output;
        while (position_ < input_.size()) {
            const unsigned char c = static_cast<unsigned char>(input_[position_++]);
            if (c == '"') {
                return output;
            }
            if (c < 0x20) {
                fail("Malformed certificate JSON string.");
            }
            if (c != '\\') {
                output.push_back(static_cast<char>(c));
                continue;
            }
            if (position_ >= input_.size()) {
                fail("Malformed certificate JSON escape.");
            }
            const char escaped = input_[position_++];
            switch (escaped) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            default: fail("Unsupported certificate JSON escape.");
            }
        }
        fail("Unterminated certificate JSON string.");
    }

    bool finished() {
        whitespace();
        return position_ == input_.size();
    }

private:
    void expect_raw(char value) {
        if (position_ >= input_.size() || input_[position_] != value) {
            fail("Malformed certificate JSON.");
        }
        ++position_;
    }

    const std::string& input_;
    std::size_t position_ = 0;
};

void append_field(std::ostringstream& output, const char* name, const std::string& value, bool comma) {
    output << '"' << name << "\":\"" << json_escape(value) << '"';
    if (comma) {
        output << ',';
    }
}

std::string read_named(Parser& parser, const char* expected) {
    const std::string name = parser.string();
    if (name != expected) {
        fail("Unexpected or out-of-order certificate field.");
    }
    parser.expect(':');
    return parser.string();
}

} // namespace

std::string json_escape(const std::string& value) {
    std::ostringstream output;
    static constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char c : value) {
        switch (c) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20) {
                output << "\\u00" << hex[c >> 4] << hex[c & 0x0f];
            } else {
                output << static_cast<char>(c);
            }
        }
    }
    return output.str();
}

std::string canonical_payload_json(const CertificatePayload& payload) {
    std::ostringstream output;
    output << '{';
    append_field(output, "version", payload.version, true);
    append_field(output, "subject", payload.subject, true);
    append_field(output, "issuer", payload.issuer, true);
    append_field(output, "public_key_algorithm", payload.public_key_algorithm, true);
    append_field(output, "public_key_pem_b64", payload.public_key_pem_b64, true);
    append_field(output, "created_utc", payload.created_utc, true);
    append_field(output, "not_before_utc", payload.not_before_utc, true);
    append_field(output, "not_after_utc", payload.not_after_utc, false);
    output << '}';
    return output.str();
}

CertificatePayload parse_canonical_payload(const std::string& json) {
    Parser parser(json);
    CertificatePayload payload;
    parser.expect('{');
    payload.version = read_named(parser, "version");
    parser.expect(',');
    payload.subject = read_named(parser, "subject");
    parser.expect(',');
    payload.issuer = read_named(parser, "issuer");
    parser.expect(',');
    payload.public_key_algorithm = read_named(parser, "public_key_algorithm");
    parser.expect(',');
    payload.public_key_pem_b64 = read_named(parser, "public_key_pem_b64");
    parser.expect(',');
    payload.created_utc = read_named(parser, "created_utc");
    parser.expect(',');
    payload.not_before_utc = read_named(parser, "not_before_utc");
    parser.expect(',');
    payload.not_after_utc = read_named(parser, "not_after_utc");
    parser.expect('}');
    if (!parser.finished() || payload.version != "1") {
        fail("Malformed certificate payload.");
    }
    return payload;
}

} // namespace pqtool

