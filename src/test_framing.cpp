// Standalone test for FrameParser. No external test framework — keeps the
// build minimal. Returns 0 on success, nonzero on first failure.
//
// Build:
//   g++ -std=c++17 -Iinc src/test_framing.cpp -o test_framing
// Run:
//   ./test_framing

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "framing.hpp"

using namespace securelink;

#define CHECK(cond) do {                                         \
    if (!(cond)) {                                               \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                 \
                     __FILE__, __LINE__, #cond);                 \
        return 1;                                                \
    }                                                            \
} while (0)

static int test_encode_decode_roundtrip() {
    const std::uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    auto wire = FrameParser::encode(FrameType::kData, 0x00,
                                    payload, sizeof(payload));
    CHECK(wire.size() == constants::FRAME_HEADER_SIZE + sizeof(payload));

    FrameParser parser;
    parser.feed(wire.data(), wire.size());

    Frame f;
    CHECK(parser.next(f) == ParseStatus::kReady);
    CHECK(f.type == FrameType::kData);
    CHECK(f.flags == 0x00);
    CHECK(f.payload.size() == sizeof(payload));
    CHECK(std::memcmp(f.payload.data(), payload, sizeof(payload)) == 0);
    CHECK(parser.buffered() == 0);
    return 0;
}

static int test_streaming_partial_feed() {
    const std::uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto wire = FrameParser::encode(FrameType::kHandshakeHi, 0x01,
                                    payload, sizeof(payload));
    FrameParser parser;
    Frame f;

    // Feed 1 byte at a time. Must report kNeedMore until the last byte.
    for (std::size_t i = 0; i + 1 < wire.size(); ++i) {
        parser.feed(&wire[i], 1);
        CHECK(parser.next(f) == ParseStatus::kNeedMore);
    }
    parser.feed(&wire.back(), 1);
    CHECK(parser.next(f) == ParseStatus::kReady);
    CHECK(f.type == FrameType::kHandshakeHi);
    CHECK(f.flags == 0x01);
    return 0;
}

static int test_two_frames_in_one_feed() {
    auto a = FrameParser::encode(FrameType::kPing,  0, nullptr, 0);
    auto b = FrameParser::encode(FrameType::kPong,  0, nullptr, 0);
    std::vector<std::uint8_t> joined;
    joined.insert(joined.end(), a.begin(), a.end());
    joined.insert(joined.end(), b.begin(), b.end());

    FrameParser parser;
    parser.feed(joined.data(), joined.size());

    Frame f1, f2;
    CHECK(parser.next(f1) == ParseStatus::kReady);
    CHECK(f1.type == FrameType::kPing);
    CHECK(parser.next(f2) == ParseStatus::kReady);
    CHECK(f2.type == FrameType::kPong);
    CHECK(parser.next(f1) == ParseStatus::kNeedMore);
    return 0;
}

static int test_oversize_rejected() {
    // Hand-craft a header claiming 10 MiB payload.
    std::uint8_t hdr[constants::FRAME_HEADER_SIZE] = {};
    const std::uint32_t big = 10 * 1024 * 1024;
    hdr[0] = (big >> 24) & 0xFF;
    hdr[1] = (big >> 16) & 0xFF;
    hdr[2] = (big >> 8)  & 0xFF;
    hdr[3] = big & 0xFF;
    hdr[4] = static_cast<std::uint8_t>(FrameType::kData);

    FrameParser parser;
    parser.feed(hdr, sizeof(hdr));
    Frame f;
    CHECK(parser.next(f) == ParseStatus::kErrorOversize);
    return 0;
}

static int test_bad_reserved_rejected() {
    std::uint8_t hdr[constants::FRAME_HEADER_SIZE] = {
        0, 0, 0, 0,                                         // length 0
        static_cast<std::uint8_t>(FrameType::kPing),
        0,
        0, 0x01,                                            // reserved nonzero
    };
    FrameParser parser;
    parser.feed(hdr, sizeof(hdr));
    Frame f;
    CHECK(parser.next(f) == ParseStatus::kErrorBadReserved);
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_encode_decode_roundtrip();
    rc |= test_streaming_partial_feed();
    rc |= test_two_frames_in_one_feed();
    rc |= test_oversize_rejected();
    rc |= test_bad_reserved_rejected();
    if (rc == 0) std::puts("test_framing: OK");
    return rc;
}
