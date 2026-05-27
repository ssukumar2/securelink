#include "sl_crc32.h"

static uint32_t g_table[256];
static int      g_table_ready = 0;

static void build_table(void) {
    const uint32_t poly = 0x82F63B78u; /* reversed 0x1EDC6F41 */
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (poly ^ (c >> 1)) : (c >> 1);
        }
        g_table[i] = c;
    }
    g_table_ready = 1;
}

uint32_t sl_crc32c_init(void) {
    return 0xFFFFFFFFu;
}

uint32_t sl_crc32c_update(uint32_t crc, const void *data, size_t len) {
    if (!g_table_ready) build_table();
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i) {
        crc = g_table[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc;
}

uint32_t sl_crc32c_finalize(uint32_t crc) {
    return crc ^ 0xFFFFFFFFu;
}

uint32_t sl_crc32c(const void *data, size_t len) {
    uint32_t crc = sl_crc32c_init();
    crc = sl_crc32c_update(crc, data, len);
    return sl_crc32c_finalize(crc);
}
