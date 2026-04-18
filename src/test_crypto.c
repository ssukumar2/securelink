#include "crypto_engine.h"
#include <stdio.h>
#include <string.h>

#define TEST(name, expr) do { \
    if (expr) { printf("  PASS: %s\n", name); passed++; } \
    else { printf("  FAIL: %s\n", name); failed++; } \
    total++; \
} while(0)

int main(void)
{
    int passed = 0, failed = 0, total = 0;

    printf("=== crypto_engine tests ===\n\n");

    /* Test 1: keypair creation */
    ecc_keypair_t* kp1 = ecc_keypair_create();
    TEST("create keypair", kp1 != NULL);

    /* Test 2: get public key */
    uint8_t pub1[64];
    int rc = ecc_get_public_key(kp1, pub1, sizeof(pub1));
    TEST("get public key", rc == 0);

    /* Test 3: public key is not all zeros */
    int nonzero = 0;
    for (int i = 0; i < 64; i++) { if (pub1[i] != 0) nonzero = 1; }
    TEST("public key is not zero", nonzero == 1);

    /* Test 4: two keypairs produce different public keys */
    ecc_keypair_t* kp2 = ecc_keypair_create();
    uint8_t pub2[64];
    ecc_get_public_key(kp2, pub2, sizeof(pub2));
    TEST("two keypairs differ", memcmp(pub1, pub2, 64) != 0);

    /* Test 5: ECDH shared secret — both sides derive same secret */
    uint8_t secret1[32], secret2[32];
    int s1 = ecc_derive_shared_secret(kp1, pub2, 64, secret1, sizeof(secret1));
    int s2 = ecc_derive_shared_secret(kp2, pub1, 64, secret2, sizeof(secret2));

    TEST("ecdh secret derivation succeeds", s1 == 32 && s2 == 32);
    TEST("both sides derive same secret", memcmp(secret1, secret2, 32) == 0);

    /* Test 7: AES encrypt then decrypt */
    uint8_t plaintext[16] = "U2VjbG91cyBHbWJI";
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    int enc = aes256_ecb_encrypt(secret1, plaintext, 16, ciphertext, sizeof(ciphertext));
    TEST("aes encrypt returns 16", enc == 16);

    int dec = aes256_ecb_decrypt(secret1, ciphertext, 16, decrypted, sizeof(decrypted));

    TEST("aes decrypt returns 16", dec == 16);
    TEST("decrypt matches original", memcmp(plaintext, decrypted, 16) == 0);

    /* Test 10: ciphertext differs from plaintext */
    TEST("ciphertext differs from plaintext", memcmp(plaintext, ciphertext, 16) != 0);

    /* Cleanup */
    ecc_keypair_free(kp1);
    ecc_keypair_free(kp2);

    printf("\n=== results: %d/%d passed, %d failed ===\n", passed, total, failed);
    return failed > 0 ? 1 : 0;
}