// End-to-end test piping FileSender into FileReceiver in-process,
// including a simulated drop+resume.
//
// Build:
//   g++ -std=c++17 -Iinc \
//       src/test_file_transfer.cpp \
//       src/file_sender.cpp src/file_receiver.cpp \
//       src/sl_file_meta.c src/sl_file_chunk.c src/sl_resume_map.c \
//       src/sl_sha256_stream.c src/sl_token_bucket.c \
//       src/sl_crc32.c src/sl_mem.c \
//       -lcrypto -lpthread -o test_file_transfer

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "file_receiver.hpp"
#include "file_sender.hpp"

using namespace securelink;

#define CHECK(cond) do {                                          \
    if (!(cond)) {                                                \
        std::fprintf(stderr, "FAIL %s:%d  %s\n",                  \
                     __FILE__, __LINE__, #cond);                  \
        return 1;                                                 \
    }                                                             \
} while (0)

static const char* kSrc = "/tmp/sl_test_src.bin";
static const char* kDir = "/tmp";
static const char* kName = "sl_test_dst.bin";

static int make_source_file(std::size_t bytes) {
    std::ofstream f(kSrc, std::ios::binary | std::ios::trunc);
    if (!f) return -1;
    for (std::size_t i = 0; i < bytes; ++i) {
        const char c = (char)((i * 31 + 7) & 0xFF);
        f.write(&c, 1);
    }
    return 0;
}

static int test_full_roundtrip(void) {
    /* 5 chunks of 4096 + a partial = 5*4096 + 1234 */
    CHECK(make_source_file(5 * 4096 + 1234) == 0);

    FileSender s(kSrc, kName, 4096);
    CHECK(s.open());

    FileReceiver r(kDir);

    /* Pipe metadata. */
    auto send_meta = [&](const std::vector<std::uint8_t>& w) {
        return r.on_meta(w.data(), w.size()) == FileRxResult::kAccepted;
    };
    CHECK(s.send_meta(send_meta));

    /* Stream all chunks; last one should return kComplete. */
    FileRxResult last = FileRxResult::kAccepted;
    auto send_chunk = [&](const std::vector<std::uint8_t>& w) {
        last = r.on_chunk(w.data(), w.size());
        return last == FileRxResult::kAccepted ||
               last == FileRxResult::kComplete;
    };
    while (s.has_more()) CHECK(s.send_next_chunk(send_chunk));
    CHECK(last == FileRxResult::kComplete);
    CHECK(r.is_complete());

    std::unlink(kSrc);
    std::string dst = std::string(kDir) + "/" + kName;
    std::unlink(dst.c_str());
    return 0;
}

static int test_duplicate_chunk_ignored(void) {
    CHECK(make_source_file(8 * 1024) == 0);

    FileSender s(kSrc, kName, 4096);
    CHECK(s.open());
    FileReceiver r(kDir);

    std::vector<std::vector<std::uint8_t>> captured_chunks;
    auto cap_meta = [&](const std::vector<std::uint8_t>& w) {
        return r.on_meta(w.data(), w.size()) == FileRxResult::kAccepted;
    };
    auto cap_chunk = [&](const std::vector<std::uint8_t>& w) {
        captured_chunks.push_back(w);
        return true;
    };
    s.send_meta(cap_meta);
    while (s.has_more()) s.send_next_chunk(cap_chunk);

    /* Replay chunk 0 first, then everything else. */
    auto first = captured_chunks.front();
    CHECK(r.on_chunk(first.data(), first.size()) == FileRxResult::kAccepted);
    CHECK(r.on_chunk(first.data(), first.size()) == FileRxResult::kDuplicate);
    for (std::size_t i = 1; i < captured_chunks.size(); ++i) {
        FileRxResult res = r.on_chunk(captured_chunks[i].data(),
                                      captured_chunks[i].size());
        CHECK(res == FileRxResult::kAccepted ||
              res == FileRxResult::kComplete);
    }
    CHECK(r.is_complete());

    std::unlink(kSrc);
    std::string dst = std::string(kDir) + "/" + kName;
    std::unlink(dst.c_str());
    return 0;
}

static int test_resume_after_drop(void) {
    CHECK(make_source_file(10 * 4096) == 0);

    FileSender s(kSrc, kName, 4096);
    CHECK(s.open());
    FileReceiver r(kDir);

    auto meta_fn = [&](const std::vector<std::uint8_t>& w) {
        return r.on_meta(w.data(), w.size()) == FileRxResult::kAccepted;
    };
    auto chunk_fn = [&](const std::vector<std::uint8_t>& w) {
        FileRxResult res = r.on_chunk(w.data(), w.size());
        return res == FileRxResult::kAccepted ||
               res == FileRxResult::kComplete;
    };

    CHECK(s.send_meta(meta_fn));

    /* Send only first 5 chunks. */
    for (int i = 0; i < 5; ++i) CHECK(s.send_next_chunk(chunk_fn));
    CHECK(!r.is_complete());

    auto missing = r.missing_chunks();
    CHECK(missing.size() == 5);
    CHECK(missing[0] == 5);

    /* Resume by rewinding the sender to chunk 5. */
    CHECK(s.seek_chunk(5));
    while (s.has_more()) CHECK(s.send_next_chunk(chunk_fn));
    CHECK(r.is_complete());

    std::unlink(kSrc);
    std::string dst = std::string(kDir) + "/" + kName;
    std::unlink(dst.c_str());
    return 0;
}

int main() {
    int rc = 0;
    rc |= test_full_roundtrip();
    rc |= test_duplicate_chunk_ignored();
    rc |= test_resume_after_drop();
    if (rc == 0) std::puts("test_file_transfer: OK");
    return rc;
}
