#include "state_store.hpp"

#include <cstring>

namespace securelink {

StateStore::StateStore(const std::string& path)
    : kv_(sl_kvstore_open(path.c_str())) {}

StateStore::~StateStore() {
    if (kv_) sl_kvstore_close(kv_);
}

bool StateStore::put_string(std::string_view key, std::string_view value) {
    if (!kv_) return false;
    return sl_kvstore_put(kv_,
                          key.data(),   key.size(),
                          value.data(), value.size()) == 0;
}

bool StateStore::put_u64(std::string_view key, std::uint64_t value) {
    if (!kv_) return false;
    std::uint8_t buf[8];
    for (int i = 0; i < 8; ++i) {
        buf[i] = static_cast<std::uint8_t>(value >> (56 - 8 * i));
    }
    return sl_kvstore_put(kv_,
                          key.data(), key.size(),
                          buf, sizeof(buf)) == 0;
}

bool StateStore::put_bytes(std::string_view key,
                           const void* data, std::size_t len) {
    if (!kv_) return false;
    return sl_kvstore_put(kv_,
                          key.data(), key.size(),
                          data, len) == 0;
}

std::optional<std::string> StateStore::get_string(std::string_view key) {
    if (!kv_) return std::nullopt;
    std::string out;
    out.resize(4096);
    std::size_t got = 0;
    int rc = sl_kvstore_get(kv_, key.data(), key.size(),
                            out.data(), out.size(), &got);
    if (rc == -3) {
        out.resize(got);
        rc = sl_kvstore_get(kv_, key.data(), key.size(),
                            out.data(), out.size(), &got);
    }
    if (rc != 0) return std::nullopt;
    out.resize(got);
    return out;
}

std::optional<std::uint64_t> StateStore::get_u64(std::string_view key) {
    if (!kv_) return std::nullopt;
    std::uint8_t buf[8];
    std::size_t got = 0;
    if (sl_kvstore_get(kv_, key.data(), key.size(),
                       buf, sizeof(buf), &got) != 0) return std::nullopt;
    if (got != 8) return std::nullopt;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | buf[i];
    return v;
}

std::optional<std::vector<std::uint8_t>>
StateStore::get_bytes(std::string_view key) {
    if (!kv_) return std::nullopt;
    std::vector<std::uint8_t> buf(4096);
    std::size_t got = 0;
    int rc = sl_kvstore_get(kv_, key.data(), key.size(),
                            buf.data(), buf.size(), &got);
    if (rc == -3) {
        buf.resize(got);
        rc = sl_kvstore_get(kv_, key.data(), key.size(),
                            buf.data(), buf.size(), &got);
    }
    if (rc != 0) return std::nullopt;
    buf.resize(got);
    return buf;
}

bool StateStore::remove(std::string_view key) {
    if (!kv_) return false;
    return sl_kvstore_delete(kv_, key.data(), key.size()) == 0;
}

bool StateStore::has(std::string_view key) {
    if (!kv_) return false;
    return sl_kvstore_has(kv_, key.data(), key.size());
}

bool StateStore::sync() {
    return kv_ && sl_kvstore_sync(kv_) == 0;
}

std::size_t StateStore::size() const {
    return kv_ ? sl_kvstore_size(kv_) : 0;
}

}  // namespace securelink
