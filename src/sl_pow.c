#include "sl_pow.h"

#include <openssl/sha.h>
#include <string.h>

#include "sl_rng.h"

int sl_pow_make_challenge(uint8_t challenge_out[SL_POW_CHALLENGE_LEN]) {
    return sl_rng_bytes(challenge_out, SL_POW_CHALLENGE_LEN);
}

static uint32_t leading_zero_bits(const uint8_t *digest, size_t len) {
    uint32_t zeros = 0;
    for (size_t i = 0; i < len; ++i) {
        if (digest[i] == 0) { zeros += 8; continue; }
        uint8_t b = digest[i];
        while ((b & 0x80) == 0) { ++zeros; b <<= 1; }
        break;
    }
    return zeros;
}

bool sl_pow_verify(const uint8_t challenge[SL_POW_CHALLENGE_LEN],
                   const uint8_t nonce[SL_POW_NONCE_LEN],
                   uint32_t      difficulty_bits) {
    if (!challenge || !nonce) return false;
    if (difficulty_bits > 256) return false;

    uint8_t input[SL_POW_CHALLENGE_LEN + SL_POW_NONCE_LEN];
    memcpy(input,                          challenge, SL_POW_CHALLENGE_LEN);
    memcpy(input + SL_POW_CHALLENGE_LEN,   nonce,     SL_POW_NONCE_LEN);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(input, sizeof(input), digest);

    return leading_zero_bits(digest, sizeof(digest)) >= difficulty_bits;
}

int sl_pow_solve(const uint8_t challenge[SL_POW_CHALLENGE_LEN],
                 uint32_t      difficulty_bits,
                 uint64_t      max_iters,
                 uint8_t       nonce_out[SL_POW_NONCE_LEN]) {
    if (!challenge || !nonce_out) return -1;

    uint8_t input[SL_POW_CHALLENGE_LEN + SL_POW_NONCE_LEN];
    memcpy(input, challenge, SL_POW_CHALLENGE_LEN);

    uint64_t counter = 0;
    /* Start from a random offset so concurrent solvers don't collide. */
    sl_rng_u64(&counter);

    for (uint64_t i = 0; i < max_iters; ++i) {
        uint64_t v = counter + i;
        for (int b = 0; b < 8; ++b) {
            input[SL_POW_CHALLENGE_LEN + b] =
                (uint8_t)(v >> (56 - 8 * b));
        }
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(input, sizeof(input), digest);
        if (leading_zero_bits(digest, sizeof(digest)) >= difficulty_bits) {
            memcpy(nonce_out, input + SL_POW_CHALLENGE_LEN, SL_POW_NONCE_LEN);
            return 0;
        }
    }
    return -1;
}
