#pragma once
/* clock_gettime, CLOCK_MONOTONIC, CLOCK_REALTIME, nanosleep, and strdup
 * are all POSIX (POSIX.1-2008), not standard C11 -- glibc hides them
 * under strict -std=c11 unless this feature-test macro is defined
 * before any system header is included.
 *
 * This exact fix showed up six separate times across the codebase
 * (sl_lockout.c, sl_dos_guard.c, sl_token_bucket.c, sl_clock.c,
 * sl_event_log.c, sl_deadline.c) as copy-pasted comment + #define
 * pairs before anyone noticed the pattern. One shared header instead.
 *
 * Must be the FIRST include in any .c file that needs it -- the macro
 * has no effect if a system header was already included above it.
 */
#ifndef SECURELINK_SL_POSIX_COMPAT_H
#define SECURELINK_SL_POSIX_COMPAT_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#endif
