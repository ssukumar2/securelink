#include "sl_canary.h"

#include <stdatomic.h>

#include "sl_mem.h"
#include "sl_rng.h"

static _Atomic uint64_t g_canary = 0;

int sl_canary_init(void) {
    uint64_t v = 0;
    if (sl_rng_u64(&v) != 0) return -1;
    /* Ensure low and high bytes are non-zero so trivial overwrites detect. */
    if ((v & 0xFFULL) == 0)              v |= 0xA5ULL;
    if ((v & 0xFF00000000000000ULL) == 0) v |= 0x5AULL << 56;
    atomic_store_explicit(&g_canary, v, memory_order_release);
    return 0;
}

uint64_t sl_canary_value(void) {
    return atomic_load_explicit(&g_canary, memory_order_acquire);
}

void sl_canary_arm(uint64_t *slot) {
    if (!slot) return;
    *slot = sl_canary_value();
}

bool sl_canary_check(const uint64_t *slot) {
    if (!slot) return false;
    const uint64_t expected = sl_canary_value();
    /* Constant-time compare to avoid leaking position of corruption. */
    return sl_ct_equal(slot, &expected, sizeof(expected)) == 1;
}

void sl_canary_disarm(uint64_t *slot) {
    if (!slot) return;
    sl_secure_zero(slot, sizeof(*slot));
}
