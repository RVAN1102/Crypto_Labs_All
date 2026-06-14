#include "random_utils.hpp"

#include <osrng.h>

Bytes random_bytes(std::size_t n) {
    Bytes out(n);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(out.data(), out.size());
    return out;
}
