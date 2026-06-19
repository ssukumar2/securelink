/* Attack: random record corruption.
 *
 * For N seeds, take a valid sealed sl_record, mutate it with a deterministic
 * fuzzer, and assert the receiver REJECTS every mutation. This is the
 * "no surprise valid record" property — the AEAD + framing should never
 * accept a randomly-corrupted record as authentic.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/attack_record_fuzz.c \
 *       src/sl_record.c src/sl_aead.c src/sl_nonce.c \
 *       src/sl_mem.c src/sl_rng.c src/sl_packet_mutator.c \
 *       -lcrypto -o attack_record_fuzz
 */

#include <stdio.h>
#include <string.h>

#include "sl_packet_mutator.h"
#include "sl_record.h"
#include "sl_rng.h"

#define ITERS 2000

static int run(void) {
    uint8_t key[SL_AEAD_KEY_LEN], iv[SL_AEAD_IV_LEN];
    sl_rng_init();
    sl_rng_bytes(key, sizeof(key));
    sl_rng_bytes(iv,  sizeof(iv));

    const char *msg = "fuzz-target plaintext bytes";
    uint8_t wire[256];
    int n = sl_record_seal(SL_REC_APP_DATA, key, iv, /*seq=*/42,
                           (const uint8_t *)msg, strlen(msg),
                           wire, sizeof(wire));
    if (n <= 0) {
        fprintf(stderr, "setup: sealing failed\n");
        return 1;
    }

    uint64_t accepts = 0;
    sl_mut_rng_t r;

    for (uint64_t i = 0; i < ITERS; ++i) {
        uint8_t copy[256];
        memcpy(copy, wire, (size_t)n);

        sl_mut_rng_seed(&r, 0xCAFEBABE ^ i);
        /* Apply 1..3 random bit flips somewhere in the record. */
        const size_t flips = 1 + (sl_mut_rng_next(&r) % 3);
        sl_mut_flip_bits(&r, copy, (size_t)n, flips);

        sl_record_type_t type;
        uint8_t pt[256];
        size_t plen = 0;
        const int rc = sl_record_open(copy, (size_t)n, key, iv, 42,
                                      &type, pt, sizeof(pt), &plen);
        if (rc == 0) ++accepts;
    }

    if (accepts != 0) {
        fprintf(stderr, "attack_record_fuzz: %llu/%d corrupted records "
                        "ACCEPTED — DEFENSE FAILED\n",
                        (unsigned long long)accepts, ITERS);
        return 1;
    }
    printf("attack_record_fuzz: 0/%d random mutations accepted — BLOCKED\n",
           ITERS);
    return 0;
}

int main(void) { return run(); }
