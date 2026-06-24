#pragma once

#include <stdexcept>
#include <string>

namespace pqtool {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

[[noreturn]] void fail(const std::string& message);

} // namespace pqtool

