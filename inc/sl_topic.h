#ifndef SECURELINK_SL_TOPIC_H
#define SECURELINK_SL_TOPIC_H

/* Topic name validation for the pub/sub layer.
 *
 * Topics are slash-separated segments: "sensors/temp/kitchen".
 * Each segment is [A-Za-z0-9_-]+. Topics may not start or end with '/'.
 *
 * Wildcards (only valid in subscription filters, never in publish topics):
 *   '+' matches exactly one segment      "sensors/+/kitchen"
 *   '#' matches zero or more trailing    "sensors/#"
 *       segments; must be the last token */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SL_TOPIC_MAX_LEN     256U
#define SL_TOPIC_MAX_SEGMENTS 16U

bool sl_topic_is_valid_publish(const char *topic, size_t len);

bool sl_topic_is_valid_filter (const char *filter, size_t len);

/* Test whether `topic` (a concrete publish topic) matches `filter`
 * (may contain wildcards). Returns true on match. */
bool sl_topic_matches(const char *topic,  size_t topic_len,
                      const char *filter, size_t filter_len);

#ifdef __cplusplus
}
#endif

#endif /* SECURELINK_SL_TOPIC_H */
