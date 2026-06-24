#include "pqtool/errors.hpp"

namespace pqtool {

[[noreturn]] void fail(const std::string& message) {
    throw Error(message);
}

} // namespace pqtool

