#include "hashtool/kat.hpp"

#include "hashtool/encoding.hpp"
#include "hashtool/hash.hpp"

#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace hashtool {

namespace {

struct KatCase {
    std::string name;
    std::string algo;
    std::string text;
    std::string expected_hex;
    std::size_t outlen = 0;
    bool has_outlen = false;
};

bool read_text_file(const std::string& path, std::string& text, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open KAT file: " + path;
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    text = ss.str();
    return true;
}

std::string unescape_json_string(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    bool escape = false;
    for (char c : value) {
        if (escape) {
            switch (c) {
            case 'n':
                out.push_back('\n');
                break;
            case 'r':
                out.push_back('\r');
                break;
            case 't':
                out.push_back('\t');
                break;
            case '\\':
            case '"':
            case '/':
                out.push_back(c);
                break;
            default:
                out.push_back(c);
                break;
            }
            escape = false;
        } else if (c == '\\') {
            escape = true;
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::map<std::string, std::string> parse_string_fields(const std::string& object) {
    std::map<std::string, std::string> fields;
    const std::regex field_re(R"json("([^"]+)"\s*:\s*"((?:\\.|[^"\\])*)")json");
    auto begin = std::sregex_iterator(object.begin(), object.end(), field_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        fields[(*it)[1].str()] = unescape_json_string((*it)[2].str());
    }
    return fields;
}

bool parse_outlen(const std::string& object, std::size_t& outlen, bool& has_outlen) {
    const std::regex outlen_re(R"("outlen"\s*:\s*([0-9]+))");
    std::smatch match;
    has_outlen = std::regex_search(object, match, outlen_re);
    if (!has_outlen) {
        outlen = 0;
        return true;
    }
    try {
        outlen = static_cast<std::size_t>(std::stoull(match[1].str()));
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_cases(const std::string& json, std::vector<KatCase>& cases, std::string& error) {
    cases.clear();
    const std::regex object_re(R"(\{[^{}]*\})");
    auto begin = std::sregex_iterator(json.begin(), json.end(), object_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        const std::string object = it->str();
        const auto fields = parse_string_fields(object);
        if (fields.find("name") == fields.end() ||
            fields.find("algo") == fields.end() ||
            fields.find("text") == fields.end() ||
            fields.find("expected_hex") == fields.end()) {
            continue;
        }

        KatCase test_case;
        test_case.name = fields.at("name");
        test_case.algo = fields.at("algo");
        test_case.text = fields.at("text");
        test_case.expected_hex = fields.at("expected_hex");
        if (!parse_outlen(object, test_case.outlen, test_case.has_outlen)) {
            error = "invalid outlen in KAT case: " + test_case.name;
            return false;
        }
        cases.push_back(test_case);
    }

    if (cases.empty()) {
        error = "no KAT cases found";
        return false;
    }
    return true;
}

} // namespace

int run_kat_file(const std::string& path) {
    std::string json;
    std::string error;
    if (!read_text_file(path, json, error)) {
        std::cerr << "KAT error: " << error << "\n";
        return 1;
    }

    std::vector<KatCase> cases;
    if (!parse_cases(json, cases, error)) {
        std::cerr << "KAT error: " << error << "\n";
        return 1;
    }

    int pass = 0;
    int fail = 0;
    for (const auto& test_case : cases) {
        HashAlgorithm algorithm;
        Bytes digest;
        const Bytes input(test_case.text.begin(), test_case.text.end());

        if (!parse_hash_algorithm(test_case.algo, algorithm)) {
            std::cout << "[FAIL] " << test_case.name << ": unsupported algorithm\n";
            ++fail;
            continue;
        }

        const std::size_t outlen = test_case.has_outlen ? test_case.outlen : 0;
        if (!hash_bytes(algorithm, input, outlen, digest, error)) {
            std::cout << "[FAIL] " << test_case.name << ": " << error << "\n";
            ++fail;
            continue;
        }

        const std::string actual = hex_encode(digest);
        if (actual == test_case.expected_hex) {
            std::cout << "[PASS] " << test_case.name << "\n";
            ++pass;
        } else {
            std::cout << "[FAIL] " << test_case.name << ": expected "
                      << test_case.expected_hex << " got " << actual << "\n";
            ++fail;
        }
    }

    const int total = pass + fail;
    std::cout << "KAT summary: pass=" << pass << " fail=" << fail << " total=" << total << "\n";
    return fail == 0 ? 0 : 1;
}

} // namespace hashtool
