/* Attack: targeted ciphertext/tag tampering and AAD substitution against
 * AES-256-GCM. Each scenario flips bytes in a specific region of a sealed
 * record and asserts that sl_aead_open detects it.
 *
 * Defense: AEAD authentication tag covering header (AAD) + ciphertext.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/attack_aead_tamper.c \
 *       src/sl_aead.c src/sl_packet_mutator.c \
 *       src/sl_mem.c src/sl_rng.c \
 *       -lcrypto -o attack_aead_tamper
 */

#include <stdio.h>
#include <string.h>

#include "sl_aead.h"
#include "sl_packet_mutator.h"
#include "sl_rng.h"

#define CHECK(cond, name) do {                                    \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL [%s] %s:%d  %s\n",                  \
                name, __FILE__, __LINE__, #cond);                 \
        return 1;                                                 \
    }                                                             \
} while (0)

static int seal_sample(uint8_t key[32], uint8_t iv[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *pt,  size_t pt_len,
                       uint8_t *ct, uint8_t tag[16]) {
    return sl_aead_seal(key, iv, aad, aad_len, pt, pt_len, ct, tag);
}

static int attack_flip_ciphertext_byte(void) {
    uint8_t key[32], iv[12], pt[64], ct[64], tag[16], out[64];
    sl_rng_init(); sl_rng_bytes(key, 32); sl_rng_bytes(iv, 12);
    memcpy(pt, "the quick brown fox jumps over the lazy dog!!!!", 47);

    CHECK(seal_sample(key, iv, NULL, 0, pt, 47, ct, tag) == 0, "flip_ct");

    sl_mut_rng_t r; sl_mut_rng_seed(&r, 0xC1A551F1ED);
    sl_mut_flip_bit(&r, ct, 47);

    /* Open MUST fail. */
    CHECK(sl_aead_open(key, iv, NULL, 0, ct, 47, tag, out) != 0, "flip_ct");
    printf("attack_aead_tamper[flip_ciphertext]: BLOCKED (tag mismatch)\n");
    return 0;
}

static int attack_flip_tag_byte(void) {
    uint8_t key[32], iv[12], pt[16] = "secret payload!", ct[16], tag[16], out[16];
    sl_rng_init(); sl_rng_bytes(key, 32); sl_rng_bytes(iv, 12);
    CHECK(seal_sample(key, iv, NULL, 0, pt, 15, ct, tag) == 0, "flip_tag");

    sl_mut_rng_t r; sl_mut_rng_seed(&r, 0xFEED1234);
    sl_mut_flip_bit(&r, tag, 16);

    CHECK(sl_aead_open(key, iv, NULL, 0, ct, 15, tag, out) != 0, "flip_tag");
    printf("attack_aead_tamper[flip_tag]: BLOCKED\n");
    return 0;
}

static int attack_swap_aad_after_seal(void) {
    uint8_t key[32], iv[12];
    const uint8_t aad1[] = "session-id-A";
    const uint8_t aad2[] = "session-id-B";
    const uint8_t pt[]   = "hello";
    uint8_t ct[5], tag[16], out[5];
    sl_rng_init(); sl_rng_bytes(key, 32); sl_rng_bytes(iv, 12);

    CHECK(seal_sample(key, iv, aad1, sizeof(aad1) - 1, pt, 5, ct, tag) == 0,
          "swap_aad");
    /* Attacker tries to use the same record under a different AAD. */
    CHECK(sl_aead_open(key, iv, aad2, sizeof(aad2) - 1, ct, 5, tag, out) != 0,
          "swap_aad");
    printf("attack_aead_tamper[swap_aad]: BLOCKED\n");
    return 0;
}

static int attack_cross_session_nonce_reuse(void) {
    /* Same key + IV but different message — opening one cipher with the
     * other's tag must fail. (Also documents why nonce reuse is fatal:
     * if attacker could reuse the SAME nonce, they could XOR-recover pt.) */
    uint8_t key[32], iv[12];
    uint8_t pt_a[5] = "AAAAA", pt_b[5] = "BBBBB";
    uint8_t ct_a[5], ct_b[5], tag_a[16], tag_b[16], out[5];
    sl_rng_init(); sl_rng_bytes(key, 32); sl_rng_bytes(iv, 12);

    seal_sample(key, iv, NULL, 0, pt_a, 5, ct_a, tag_a);
    seal_sample(key, iv, NULL, 0, pt_b, 5, ct_b, tag_b);

    /* Try B's ciphertext with A's tag. */
    CHECK(sl_aead_open(key, iv, NULL, 0, ct_b, 5, tag_a, out) != 0,
          "cross_tag");
    printf("attack_aead_tamper[cross_tag]: BLOCKED\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= attack_flip_ciphertext_byte();
    rc |= attack_flip_tag_byte();
    rc |= attack_swap_aad_after_seal();
    rc |= attack_cross_session_nonce_reuse();
    if (rc == 0) puts("attack_aead_tamper: ALL DEFENSES HELD");
    return rc;
}
