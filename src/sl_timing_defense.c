#include "sl_timing_defense.h"

#include <openssl/sha.h>
#include <time.h>

#include "sl_rng.h"

uint64_t sl_timing_now_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

static void sleep_us(uint64_t us) {
    if (us == 0) return;
    struct timespec ts;
    ts.tv_sec  = (time_t)(us / 1000000ULL);
    ts.tv_nsec = (long)((us % 1000000ULL) * 1000ULL);
    nanosleep(&ts, NULL);
}

void sl_timing_pad_to_floor(uint64_t start_us, uint32_t floor_us) {
    const uint64_t now = sl_timing_now_us();
    if (now >= start_us + floor_us) return;
    sleep_us(start_us + floor_us - now);
}

void sl_timing_random_jitter(uint32_t max_us) {
    if (max_us == 0) return;
    uint64_t r = 0;
    if (sl_rng_uniform((uint64_t)max_us + 1, &r) != 0) return;
    sleep_us(r);
}

void sl_timing_dummy_work(uint32_t iterations) {
    uint8_t block[64] = {0};
    uint8_t digest[SHA256_DIGEST_LENGTH];

    /* Force the compiler to keep the loop by feeding output back as input. */
    for (uint32_t i = 0; i < iterations; ++i) {
        SHA256(block, sizeof(block), digest);
        /* Mix digest into block to prevent hoisting. */
        for (size_t j = 0; j < sizeof(block); ++j) {
            block[j] ^= digest[j % SHA256_DIGEST_LENGTH];
        }
    }
    /* Volatile read prevents dead-code elimination. */
    volatile uint8_t sink = block[0];
    (void)sink;
}
