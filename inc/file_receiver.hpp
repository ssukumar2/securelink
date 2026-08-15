#pragma once
// FileReceiver — accepts metadata, then chunks, writes them to disk in
// the correct order regardless of arrival order (sparse writes via
// pwrite), maintains a resume bitmap, and verifies SHA-256 at the end.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "sl_file_meta.h"
#include "sl_resume_map.h"
#include "sl_sha256_stream.h"

namespace securelink {

enum class FileRxResult {
    kAccepted,
    kDuplicate,        // already had this chunk
    kBadChunk,         // CRC, out-of-range, oversize
    kBadMeta,
    kComplete,         // accepted AND now done
    kHashMismatch,     // complete but SHA-256 didn't match
    kIoError,
};

struct FileReceiverStats {
    std::uint32_t chunks_received   = 0;
    std::uint32_t duplicates        = 0;
    std::uint32_t bad_chunks        = 0;
    std::uint64_t bytes_received    = 0;
};

class FileReceiver {
public:
    explicit FileReceiver(std::string destination_dir);
    ~FileReceiver();

    FileReceiver(const FileReceiver&)            = delete;
    FileReceiver& operator=(const FileReceiver&) = delete;

    // Accept the initial metadata frame. Allocates the local sparse file
    // and the resume bitmap.
    FileRxResult on_meta(const std::uint8_t* wire, std::size_t len);

    // Accept one chunk wire frame.
    FileRxResult on_chunk(const std::uint8_t* wire, std::size_t len);

    bool         is_complete() const;
    const sl_file_meta_t* meta() const;
    const FileReceiverStats& stats() const { return stats_; }
    const std::string&       destination_path() const { return dest_path_; }

    // Indices of currently missing chunks (for retry NACKs).
    std::vector<std::uint32_t> missing_chunks(std::size_t max = 64) const;

private:
    bool open_dest_file();

    std::string                          dest_dir_;
    std::string                          dest_path_;
    int                                  fd_ = -1;
    bool                                 meta_set_ = false;
    sl_file_meta_t                       meta_{};
    sl_resume_map_t                      resume_{};
    sl_sha256_stream_t*                  hasher_ = nullptr;
    bool                                 hash_done_ = false;
    FileReceiverStats                    stats_;
};

}  // namespace securelink
