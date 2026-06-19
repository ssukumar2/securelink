/* Attack: handshake downgrade.
 *
 * An on-path attacker tampers with the client's supported_versions
 * extension to strip the strongest version, hoping to coerce both peers
 * onto a weaker one. (Securelink only has v1.0 today, but the defense
 * — protocol_version alert when no overlap remains — is the right
 * structural test.)
 *
 * Defense: sl_version_choose returns 0 with no overlap; the server must
 * abort with SL_DIAG_VERSION_MISMATCH.
 *
 * Build:
 *   gcc -std=c11 -Iinc \
 *       src/attack_handshake_downgrade.c \
 *       src/sl_version.c \
 *       -o attack_handshake_downgrade
 */

#include <stdio.h>
#include <string.h>

#include "sl_version.h"

#define CHECK(cond, name) do {                                    \
    if (!(cond)) {                                                \
        fprintf(stderr, "FAIL [%s] %s:%d  %s\n",                  \
                name, __FILE__, __LINE__, #cond);                 \
        return 1;                                                 \
    }                                                             \
} while (0)

static int attack_no_overlap_after_strip(void) {
    /* Client offered {0x0100}; attacker strips it. Server only supports
     * {0x0100}. Result: sl_version_choose returns 0 → connection refused. */
    sl_version_list_t stripped_client, server;
    sl_version_list_init(&stripped_client);
    sl_version_list_init(&server);
    sl_version_list_add(&server, 0x0100);
    /* stripped_client is empty after the attack */

    const uint16_t chosen = sl_version_choose(&stripped_client, &server);
    CHECK(chosen == 0, "strip");
    printf("attack_handshake_downgrade[strip]: BLOCKED (no overlap)\n");
    return 0;
}

static int attack_inject_only_weak(void) {
    /* Attacker rewrites the list to claim only a fictional weaker version
     * 0x0001 the server has never supported. */
    sl_version_list_t forged_client, server;
    sl_version_list_init(&forged_client);
    sl_version_list_init(&server);
    sl_version_list_add(&forged_client, 0x0001);
    sl_version_list_add(&server,        0x0100);

    const uint16_t chosen = sl_version_choose(&forged_client, &server);
    CHECK(chosen == 0, "forge_weak");
    printf("attack_handshake_downgrade[forge_weak]: BLOCKED\n");
    return 0;
}

static int defense_highest_is_chosen(void) {
    /* Sanity check the picker really does prefer the highest. */
    sl_version_list_t a, b;
    sl_version_list_init(&a);
    sl_version_list_init(&b);
    sl_version_list_add(&a, 0x0100);
    sl_version_list_add(&a, 0x0102);
    sl_version_list_add(&a, 0x0200);
    sl_version_list_add(&b, 0x0100);
    sl_version_list_add(&b, 0x0200);

    CHECK(sl_version_choose(&a, &b) == 0x0200, "highest");
    printf("attack_handshake_downgrade[highest_invariant]: HELD\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= attack_no_overlap_after_strip();
    rc |= attack_inject_only_weak();
    rc |= defense_highest_is_chosen();
    if (rc == 0) puts("attack_handshake_downgrade: ALL DEFENSES HELD");
    return rc;
}
