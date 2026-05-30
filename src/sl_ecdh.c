#include "sl_ecdh.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <string.h>

#include "sl_mem.h"

struct sl_ecdh_keypair {
    EC_KEY *key;
};

sl_ecdh_keypair_t *sl_ecdh_keypair_new(void) {
    sl_ecdh_keypair_t *kp = (sl_ecdh_keypair_t *)calloc(1, sizeof(*kp));
    if (!kp) return NULL;
    kp->key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!kp->key) { free(kp); return NULL; }
    if (EC_KEY_generate_key(kp->key) != 1) {
        EC_KEY_free(kp->key);
        free(kp);
        return NULL;
    }
    return kp;
}

void sl_ecdh_keypair_free(sl_ecdh_keypair_t *kp) {
    if (!kp) return;
    if (kp->key) EC_KEY_free(kp->key);   /* zeroes the private key */
    sl_secure_zero(kp, sizeof(*kp));
    free(kp);
}

int sl_ecdh_export_pubkey(const sl_ecdh_keypair_t *kp,
                          uint8_t out[SL_ECDH_PUBKEY_LEN]) {
    if (!kp || !kp->key || !out) return -1;
    const EC_GROUP *grp = EC_KEY_get0_group(kp->key);
    const EC_POINT *pt  = EC_KEY_get0_public_key(kp->key);
    if (!grp || !pt) return -1;

    const size_t n = EC_POINT_point2oct(grp, pt,
                                        POINT_CONVERSION_UNCOMPRESSED,
                                        out, SL_ECDH_PUBKEY_LEN, NULL);
    return (n == SL_ECDH_PUBKEY_LEN) ? 0 : -1;
}

int sl_ecdh_validate_pubkey(const uint8_t pub[SL_ECDH_PUBKEY_LEN]) {
    if (!pub) return -1;
    if (pub[0] != 0x04) return -1;

    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!grp) return -1;
    EC_POINT *pt = EC_POINT_new(grp);
    int rc = -1;
    if (pt && EC_POINT_oct2point(grp, pt, pub, SL_ECDH_PUBKEY_LEN, NULL) == 1 &&
        EC_POINT_is_on_curve(grp, pt, NULL) == 1 &&
        EC_POINT_is_at_infinity(grp, pt) == 0) {
        rc = 0;
    }
    if (pt)  EC_POINT_free(pt);
    if (grp) EC_GROUP_free(grp);
    return rc;
}

int sl_ecdh_compute_shared(const sl_ecdh_keypair_t *kp,
                           const uint8_t peer_pub[SL_ECDH_PUBKEY_LEN],
                           uint8_t out[SL_ECDH_SHARED_LEN]) {
    if (!kp || !kp->key || !peer_pub || !out) return -1;
    if (sl_ecdh_validate_pubkey(peer_pub) != 0) return -1;

    const EC_GROUP *grp = EC_KEY_get0_group(kp->key);
    EC_POINT *peer_pt = EC_POINT_new(grp);
    int rc = -1;

    if (peer_pt &&
        EC_POINT_oct2point(grp, peer_pt, peer_pub, SL_ECDH_PUBKEY_LEN, NULL) == 1) {
        int n = ECDH_compute_key(out, SL_ECDH_SHARED_LEN, peer_pt, kp->key, NULL);
        if (n == SL_ECDH_SHARED_LEN) rc = 0;
    }
    if (peer_pt) EC_POINT_free(peer_pt);
    return rc;
}
