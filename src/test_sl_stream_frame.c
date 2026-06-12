/* Tests for sl_stream_frame.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/test_sl_stream_frame.c src/sl_stream_frame.c \
 *       -o test_sl_stream_frame
 */

#include <stdio.h>
#include <string.h>

#include "sl_stream_frame.h"

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL %s:%d  %s\n",                       \
                __FILE__, __LINE__, #cond);                       \
        return 1;                                                 \
    }                                                             \
} while (0)

static int test_pack_unpack_roundtrip(void) {
    const uint8_t body[] = {0xDE, 0xAD, 0xBE, 0xEF};
    sl_stream_frame_t in = {
        .type        = SL_STREAM_FRAME_DATA,
        .flags       = SL_STREAM_FLAG_OPEN,
        .stream_id   = 7,
        .payload     = body,
        .payload_len = sizeof(body),
    };
    uint8_t wire[64];
    int n = sl_stream_frame_pack(&in, wire, sizeof(wire));
    CHECK(n == (int)(SL_STREAM_FRAME_HEADER_LEN + sizeof(body)));

    sl_stream_frame_t out;
    int m = sl_stream_frame_unpack(wire, (size_t)n, &out);
    CHECK(m == n);
    CHECK(out.type == SL_STREAM_FRAME_DATA);
    CHECK(out.flags == SL_STREAM_FLAG_OPEN);
    CHECK(out.stream_id == 7);
    CHECK(out.payload_len == sizeof(body));
    CHECK(memcmp(out.payload, body, sizeof(body)) == 0);
    return 0;
}

static int test_zero_payload(void) {
    sl_stream_frame_t in = {
        .type      = SL_STREAM_FRAME_PING,
        .flags     = 0,
        .stream_id = 0,
        .payload   = NULL,
        .payload_len = 0,
    };
    uint8_t wire[16];
    int n = sl_stream_frame_pack(&in, wire, sizeof(wire));
    CHECK(n == SL_STREAM_FRAME_HEADER_LEN);

    sl_stream_frame_t out;
    CHECK(sl_stream_frame_unpack(wire, (size_t)n, &out) == n);
    CHECK(out.type == SL_STREAM_FRAME_PING);
    CHECK(out.payload_len == 0);
    return 0;
}

static int test_bad_reserved_rejected(void) {
    uint8_t wire[SL_STREAM_FRAME_HEADER_LEN] = {
        SL_STREAM_FRAME_DATA, 0,
        0x00, 0x01,                /* reserved nonzero */
        0, 0, 0, 1,
        0, 0,
    };
    sl_stream_frame_t out;
    CHECK(sl_stream_frame_unpack(wire, sizeof(wire), &out) < 0);
    return 0;
}

static int test_truncated_payload_rejected(void) {
    uint8_t wire[SL_STREAM_FRAME_HEADER_LEN + 1] = {
        SL_STREAM_FRAME_DATA, 0,
        0, 0,
        0, 0, 0, 3,
        0, 10,           /* claims 10 bytes, only 1 follows */
        0xAA,
    };
    sl_stream_frame_t out;
    CHECK(sl_stream_frame_unpack(wire, sizeof(wire), &out) < 0);
    return 0;
}

static int test_unknown_type_rejected(void) {
    uint8_t wire[SL_STREAM_FRAME_HEADER_LEN] = {
        99, 0,
        0, 0,
        0, 0, 0, 1,
        0, 0,
    };
    sl_stream_frame_t out;
    CHECK(sl_stream_frame_unpack(wire, sizeof(wire), &out) < 0);
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_pack_unpack_roundtrip();
    rc |= test_zero_payload();
    rc |= test_bad_reserved_rejected();
    rc |= test_truncated_payload_rejected();
    rc |= test_unknown_type_rejected();
    if (rc == 0) puts("test_sl_stream_frame: OK");
    return rc;
}
