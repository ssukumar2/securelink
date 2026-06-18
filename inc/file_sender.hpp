#pragma once
// FileSender — sends one file as a sequence of metadata + chunks.
//
// Usage:
//   FileSender s("/path/to/file.bin", "file.bin");
//   if (!s.open()) { ... }
//   s.send_meta(send_fn);            // emit metadata
//   while (s.has_more()) {
//       s.send_next_chunk(send_fn);
//   }
//
// Supports rewind to a specific chunk index for resume support, plus an
// optional token bucket to throttle bandwidth.

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "sl_file_meta.h"
#include "sl_token_bucket.h"

namespace securelink {

using FileSendFn = std::function<bool(const std::vector<std::uint8_t>&)>;

struct FileSenderStats {
    std::uint32_t chunks_sent   = 0;
    std::uint64_t bytes_sent    = 0;
    std::uint32_t throttle_hits = 0;
};

class FileSender {
public:
    FileSender(std::string source_path,
               std::string wire_name,
               std::uint32_t chunk_size = 16U * 1024U);
    ~FileSender();

    bool open();                                        // computes meta + opens fd
    bool send_meta(const FileSendFn& send);             // emit metadata frame
    bool send_next_chunk(const FileSendFn& send);       // emit next pending chunk

    bool seek_chunk(std::uint32_t chunk_index);         // resume to a given chunk
    bool has_more() const;

    const sl_file_meta_t& meta() const { return meta_; }

    void set_throttle(std::uint64_t capacity_bytes, std::uint64_t rate_bps);

    const FileSenderStats& stats() const { return stats_; }

private:
    bool compute_meta();

    std::string         source_;
    std::string         wire_name_;
    std::uint32_t       chunk_size_;
    int                 fd_ = -1;
    sl_file_meta_t      meta_{};
    std::uint32_t       next_idx_ = 0;
    std::unique_ptr<sl_token_bucket_t> bucket_;
    FileSenderStats     stats_;
};

}  // namespace securelink
