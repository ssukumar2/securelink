#include "file_receiver.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>

#include "sl_file_chunk.h"
#include "sl_mem.h"

namespace securelink {

FileReceiver::FileReceiver(std::string destination_dir)
    : dest_dir_(std::move(destination_dir)) {}

FileReceiver::~FileReceiver() {
    if (fd_ >= 0) ::close(fd_);
    if (hasher_) sl_sha256_stream_free(hasher_);
    if (resume_.bits) sl_resume_map_free(&resume_);
}

bool FileReceiver::open_dest_file() {
    dest_path_ = dest_dir_ + "/" + meta_.name;
    fd_ = ::open(dest_path_.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd_ < 0) return false;
    if (meta_.total_size > 0) {
        if (::ftruncate(fd_, (off_t)meta_.total_size) != 0) return false;
    }
    return true;
}

FileRxResult FileReceiver::on_meta(const std::uint8_t* wire, std::size_t len) {
    if (meta_set_) return FileRxResult::kBadMeta;
    if (sl_file_meta_unpack(wire, len, &meta_) != 0) {
        return FileRxResult::kBadMeta;
    }
    if (sl_resume_map_init(&resume_, meta_.total_chunks) != 0) {
        return FileRxResult::kIoError;
    }
    hasher_ = sl_sha256_stream_new();
    if (!hasher_) return FileRxResult::kIoError;
    if (!open_dest_file()) return FileRxResult::kIoError;
    meta_set_ = true;
    return FileRxResult::kAccepted;
}

FileRxResult FileReceiver::on_chunk(const std::uint8_t* wire, std::size_t len) {
    if (!meta_set_) return FileRxResult::kBadMeta;

    sl_file_chunk_t c{};
    if (sl_file_chunk_unpack(wire, len, &c) != 0) {
        ++stats_.bad_chunks; return FileRxResult::kBadChunk;
    }
    if (c.chunk_index >= meta_.total_chunks) {
        ++stats_.bad_chunks; return FileRxResult::kBadChunk;
    }
    if (c.data_len > meta_.chunk_size) {
        ++stats_.bad_chunks; return FileRxResult::kBadChunk;
    }
    /* Last chunk may be short; all others must be exactly chunk_size. */
    if (c.chunk_index + 1 < meta_.total_chunks &&
        c.data_len != meta_.chunk_size) {
        ++stats_.bad_chunks; return FileRxResult::kBadChunk;
    }
    if (!sl_file_chunk_crc_ok(&c)) {
        ++stats_.bad_chunks; return FileRxResult::kBadChunk;
    }
    if (sl_resume_map_has(&resume_, c.chunk_index)) {
        ++stats_.duplicates;
        return FileRxResult::kDuplicate;
    }

    const std::uint64_t off = (std::uint64_t)c.chunk_index * meta_.chunk_size;
    if (c.data_len > 0) {
        std::size_t written = 0;
        while (written < c.data_len) {
            ssize_t n = ::pwrite(fd_, c.data + written,
                                 c.data_len - written,
                                 (off_t)(off + written));
            if (n <= 0) return FileRxResult::kIoError;
            written += (std::size_t)n;
        }
    }

    sl_resume_map_set(&resume_, c.chunk_index);
    ++stats_.chunks_received;
    stats_.bytes_received += c.data_len;

    if (!sl_resume_map_complete(&resume_)) {
        return FileRxResult::kAccepted;
    }

    /* All chunks present — verify hash by streaming the file from disk. */
    if (hash_done_) return FileRxResult::kComplete;

    if (::lseek(fd_, 0, SEEK_SET) < 0) return FileRxResult::kIoError;
    std::uint8_t buf[16 * 1024];
    for (;;) {
        ssize_t n = ::read(fd_, buf, sizeof(buf));
        if (n < 0)  return FileRxResult::kIoError;
        if (n == 0) break;
        sl_sha256_stream_update(hasher_, buf, (std::size_t)n);
    }
    std::uint8_t digest[SL_SHA256_DIGEST_LEN];
    if (sl_sha256_stream_finalize(hasher_, digest) != 0) {
        return FileRxResult::kIoError;
    }
    hash_done_ = true;
    if (sl_ct_equal(digest, meta_.sha256, SL_SHA256_DIGEST_LEN) != 1) {
        return FileRxResult::kHashMismatch;
    }
    return FileRxResult::kComplete;
}

bool FileReceiver::is_complete() const {
    return meta_set_ && sl_resume_map_complete(&resume_) && hash_done_;
}

const sl_file_meta_t* FileReceiver::meta() const {
    return meta_set_ ? &meta_ : nullptr;
}

std::vector<std::uint32_t> FileReceiver::missing_chunks(std::size_t max) const {
    std::vector<std::uint32_t> out(max);
    bool more = false;
    const std::size_t got = sl_resume_map_missing(&resume_,
                                                  out.data(), out.size(), &more);
    out.resize(got);
    return out;
}

}  // namespace securelink
