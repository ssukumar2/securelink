#pragma once
// StateStore — type-safe C++ facade over the C sl_kvstore.
//
// Provides typed put/get for strings, integers, and arbitrary byte spans.
// Also offers a namespaced view (StateStoreView) so different subsystems
// can share one file without colliding key names.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sl_kvstore.h"

namespace securelink {

class StateStore {
public:
    explicit StateStore(const std::string& path);
    ~StateStore();

    StateStore(const StateStore&)            = delete;
    StateStore& operator=(const StateStore&) = delete;

    bool ok() const { return kv_ != nullptr; }

    // Typed setters
    bool put_string(std::string_view key, std::string_view value);
    bool put_u64   (std::string_view key, std::uint64_t value);
    bool put_bytes (std::string_view key, const void* data, std::size_t len);

    // Typed getters
    std::optional<std::string>            get_string(std::string_view key);
    std::optional<std::uint64_t>          get_u64   (std::string_view key);
    std::optional<std::vector<std::uint8_t>> get_bytes(std::string_view key);

    bool remove(std::string_view key);
    bool has   (std::string_view key);

    bool sync();
    std::size_t size() const;

private:
    sl_kvstore_t* kv_ = nullptr;
};

class StateStoreView {
public:
    StateStoreView(StateStore& store, std::string prefix)
        : store_(store), prefix_(std::move(prefix)) {}

    bool put_string(std::string_view key, std::string_view value) {
        return store_.put_string(make(key), value);
    }
    std::optional<std::string> get_string(std::string_view key) {
        return store_.get_string(make(key));
    }
    bool put_u64(std::string_view key, std::uint64_t v) {
        return store_.put_u64(make(key), v);
    }
    std::optional<std::uint64_t> get_u64(std::string_view key) {
        return store_.get_u64(make(key));
    }
    bool remove(std::string_view key) { return store_.remove(make(key)); }
    bool has   (std::string_view key) { return store_.has   (make(key)); }

private:
    std::string make(std::string_view key) const {
        std::string out;
        out.reserve(prefix_.size() + 1 + key.size());
        out.append(prefix_);
        out.push_back(':');
        out.append(key);
        return out;
    }

    StateStore& store_;
    std::string prefix_;
};

}  // namespace securelink
