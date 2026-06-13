#ifndef SECURELINK_SL_RPC_METHOD_H
#define SECURELINK_SL_RPC_METHOD_H

/* RPC method-name validation.
 *
 * Methods are dotted segments of [A-Za-z0-9_]+ separated by '.':
 *   "echo"
 *   "fs.read_file"
 *   "auth.identity.fingerprint"
 *
 * Length is bounded at 128 chars (matches sl_rpc_msg's wire cap).
 * The validator runs in O(n) with no allocation. */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_RPC_METHOD_NAME_MAX 128U

bool sl_rpc_method_is_valid(const char *method, size_t len);

/* Split method into (namespace, leaf). For "fs.read_file":
 *   ns="fs", leaf="read_file".
 * For a bare "echo": ns="", leaf="echo".
 *
 * Returns 0 on success, -1 on invalid input. Output buffers must each
 * be at least SL_RPC_METHOD_NAME_MAX + 1 bytes. */
int  sl_rpc_method_split(const char *method, size_t len,
                         char *ns_out, char *leaf_out);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_RPC_METHOD_H */
