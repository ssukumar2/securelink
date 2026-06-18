#include "file_sender.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>

#include "sl_file_chunk.h"
#include "sl_sha256_stream.h"

namespace securelink {

FileSender::FileSender(std::string source_path,
                       std::string wire_name,
                       std::uint32_t chunk_size)
    : source_(std::move(source_path)),
      wire_name_(std::move(wire_name)),
      chunk_size_(chunk_size) {}

FileSender::~FileSender() {
    if (fd_ >= 0) ::close(fd_);
}

bool FileSender::open() {
    if (chunk_size_ < SL_FILE_CHUNK_MIN || chunk_size_ > SL_FILE_CHUNK_MAX) {
        return false;
    }
    fd_ = ::open(source_.c_str(), O_RDONLY);
    if (fd_ < 0) return false;
    return compute_meta();
}

bool FileSender::compute_meta() {
    struct stat st;
    if (::fstat(fd_, &st) != 0) return false;

    meta_.total_size   = (std::uint64_t)st.st_size;
    meta_.chunk_size   = chunk_size_;
    meta_.total_chunks = (meta_.total_size == 0) ? 0 :
        (std::uint32_t)((meta_.total_size + chunk_size_ - 1) / chunk_size_);
    meta_.mode         = (std::uint32_t)(st.st_mode & 0777);
    meta_.mtime_s      = (std::uint32_t)st.st_mtime;

    /* Compute SHA-256 of the whole file. */
    auto* h = sl_sha256_stream_new();
    if (!h) return false;

    std::vector<std::uint8_t> buf(chunk_size_);
    if (::lseek(fd_, 0, SEEK_SET) < 0) { sl_sha256_stream_free(h); return false; }
    for (;;) {
        ssize_t n = ::read(fd_, buf.data(), buf.size());
        if (n < 0)  { sl_sha256_stream_free(h); return false; }
        if (n == 0) break;
        sl_sha256_stream_update(h, buf.data(), (std::size_t)n);
    }
    sl_sha256_stream_finalize(h, meta_.sha256);
    sl_sha256_stream_free(h);

    if (wire_name_.size() > SL_FILE_NAME_MAX) return false;
    std::memcpy(meta_.name, wire_name_.data(), wire_name_.size());
    meta_.name[wire_name_.size()] = '\0';
    meta_.name_len = (std::uint16_t)wire_name_.size();

    if (::lseek(fd_, 0, SEEK_SET) < 0) return false;
    next_idx_ = 0;
    return sl_file_meta_validate(&meta_) == 0;
}

bool FileSender::send_meta(const FileSendFn& send) {
    std::vector<std::uint8_t> wire(SL_FILE_META_FIXED_LEN + meta_.name_len);
    int n = sl_file_meta_pack(&meta_, wire.data(), wire.size());
    if (n < 0) return false;
    wire.resize((std::size_t)n);
    return send(wire);
}

bool FileSender::send_next_chunk(const FileSendFn& send) {
    if (!has_more()) return false;

    /* Throttle. */
    if (bucket_) {
        if (sl_token_bucket_try_take(bucket_.get(), chunk_size_) != 0) {
            ++stats_.throttle_hits;
            return false;
        }
    }

    const std::uint64_t off = (std::uint64_t)next_idx_ * chunk_size_;
    if (::lseek(fd_, (off_t)off, SEEK_SET) < 0) return false;

    std::vector<std::uint8_t> data(chunk_size_);
    ssize_t got = ::read(fd_, data.data(), data.size());
    if (got <= 0) return false;
    data.resize((std::size_t)got);

    sl_file_chunk_t c{};
    c.chunk_index = next_idx_;
    c.data_len    = (std::uint32_t)data.size();
    c.data        = data.data();
    c.flags       = (next_idx_ + 1 == meta_.total_chunks)
                       ? SL_FILE_CHUNK_FLAG_LAST : 0;

    std::vector<std::uint8_t> wire(SL_FILE_CHUNK_HEADER_LEN + data.size());
    int n = sl_file_chunk_pack(&c, wire.data(), wire.size());
    if (n < 0) return false;
    wire.resize((std::size_t)n);

    if (!send(wire)) return false;
    ++stats_.chunks_sent;
    stats_.bytes_sent += data.size();
    ++next_idx_;
    return true;
}

bool FileSender::seek_chunk(std::uint32_t chunk_index) {
    if (chunk_index > meta_.total_chunks) return false;
    next_idx_ = chunk_index;
    return true;
}

bool FileSender::has_more() const {
    return next_idx_ < meta_.total_chunks;
}

void FileSender::set_throttle(std::uint64_t capacity_bytes,
                              std::uint64_t rate_bps) {
    bucket_.reset(new sl_token_bucket_t);
    sl_token_bucket_init(bucket_.get(), capacity_bytes, rate_bps);
}

}  // namespace securelink
