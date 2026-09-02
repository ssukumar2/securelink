// Verifies sl_transcript_* -- the running hash over every handshake
// message that Finished MACs and signatures are computed against. This
// file compiled fine on its own but was never exercised end to end by
// any test until now, despite being the property everything else in
// the handshake (Finished MAC, master secret derivation) depends on.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_transcript.cpp src/sl_transcript.c \
//       -lcrypto -o test_transcript

#include <stdio.h>
#include <string.h>
#include "sl_transcript.h"

int main(void) {
    int fail = 0;

    const char *msg_a = "client_hello_bytes_here";
    const char *msg_b = "server_hello_bytes_here";

    sl_transcript_t t1, t2;
    sl_transcript_init(&t1);
    sl_transcript_init(&t2);
    sl_transcript_update(&t1, msg_a, strlen(msg_a));
    sl_transcript_update(&t1, msg_b, strlen(msg_b));
    sl_transcript_update(&t2, msg_a, strlen(msg_a));
    sl_transcript_update(&t2, msg_b, strlen(msg_b));

    uint8_t h1[SL_TRANSCRIPT_LEN], h2[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&t1, h1);
    sl_transcript_get(&t2, h2);
    if (memcmp(h1, h2, SL_TRANSCRIPT_LEN) != 0) {
        printf("FAIL: same update sequence produced different hashes\n"); fail = 1;
    } else {
        printf("PASS: deterministic given the same message sequence\n");
    }

    sl_transcript_t t3;
    sl_transcript_init(&t3);
    sl_transcript_update(&t3, msg_b, strlen(msg_b));
    sl_transcript_update(&t3, msg_a, strlen(msg_a));
    uint8_t h3[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&t3, h3);
    if (memcmp(h1, h3, SL_TRANSCRIPT_LEN) == 0) {
        printf("FAIL: swapping message order produced the SAME hash\n"); fail = 1;
    } else {
        printf("PASS: message order changes the hash (as it must)\n");
    }

    const char *msg_a_tampered = "client_hello_bytes_hers";
    sl_transcript_t t4;
    sl_transcript_init(&t4);
    sl_transcript_update(&t4, msg_a_tampered, strlen(msg_a_tampered));
    sl_transcript_update(&t4, msg_b, strlen(msg_b));
    uint8_t h4[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&t4, h4);
    if (memcmp(h1, h4, SL_TRANSCRIPT_LEN) == 0) {
        printf("FAIL: a single tampered byte produced the SAME hash\n"); fail = 1;
    } else {
        printf("PASS: a single tampered byte changes the hash\n");
    }

    uint8_t h1_again[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&t1, h1_again);
    if (memcmp(h1, h1_again, SL_TRANSCRIPT_LEN) != 0) {
        printf("FAIL: calling get() twice in a row gave different results\n"); fail = 1;
    } else {
        printf("PASS: get() is a stable snapshot, not a finalize\n");
    }
    const char *msg_c = "finished_message_bytes";
    sl_transcript_update(&t1, msg_c, strlen(msg_c));
    uint8_t h1_extended[SL_TRANSCRIPT_LEN];
    sl_transcript_get(&t1, h1_extended);
    if (memcmp(h1, h1_extended, SL_TRANSCRIPT_LEN) == 0) {
        printf("FAIL: updating after a get() did not change the hash\n"); fail = 1;
    } else {
        printf("PASS: update() after get() correctly extends the running hash\n");
    }

    uint8_t labelled[SL_TRANSCRIPT_LEN];
    sl_transcript_labelled(&t1, "client finished", labelled);
    if (memcmp(h1_extended, labelled, SL_TRANSCRIPT_LEN) == 0) {
        printf("FAIL: labelled hash is identical to the plain hash\n"); fail = 1;
    } else {
        printf("PASS: labelled hash differs from the plain hash\n");
    }
    uint8_t labelled2[SL_TRANSCRIPT_LEN];
    sl_transcript_labelled(&t1, "server finished", labelled2);
    if (memcmp(labelled, labelled2, SL_TRANSCRIPT_LEN) == 0) {
        printf("FAIL: two different labels produced the same hash\n"); fail = 1;
    } else {
        printf("PASS: different labels produce different hashes\n");
    }

    const uint64_t expected = strlen(msg_a) + strlen(msg_b) + strlen(msg_c);
    if (sl_transcript_bytes(&t1) != expected) {
        printf("FAIL: byte counter is %llu, expected %llu\n",
               (unsigned long long)sl_transcript_bytes(&t1),
               (unsigned long long)expected);
        fail = 1;
    } else {
        printf("PASS: byte counter tracks the correct cumulative total\n");
    }

    printf(fail ? "\ntest_transcript: FAIL\n" : "\ntest_transcript: OK\n");
    return fail;
}
