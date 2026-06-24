#include "pqtool/encoding.hpp"

#include <gtest/gtest.h>

TEST(Encoding, Base64Roundtrip) {
    const pqtool::Bytes input{0x00, 0x01, 0x7f, 0x80, 0xff, 'a', 'b', 'c'};
    EXPECT_EQ(pqtool::base64_decode(pqtool::base64_encode(input)), input);
    EXPECT_THROW(pqtool::base64_decode("bad*"), std::exception);
}

TEST(Encoding, HexRoundtrip) {
    const pqtool::Bytes input{0x00, 0x01, 0xab, 0xcd, 0xef, 0xff};
    EXPECT_EQ(pqtool::hex_decode(pqtool::hex_encode(input)), input);
    EXPECT_THROW(pqtool::hex_decode("xyz"), std::exception);
}

