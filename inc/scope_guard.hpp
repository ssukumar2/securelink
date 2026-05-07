#pragma once
// Lightweight scope-exit guard. Useful for OpenSSL handles and fds where
// the C API doesn't give us RAII for free.
//
// Usage:
//   auto fd = ::socket(AF_INET, SOCK_STREAM, 0);
//   auto guard = securelink::make_scope_guard([&]{ ::close(fd); });
//   ...
//   guard.dismiss();   // if you want to keep the resource

#include <type_traits>
#include <utility>

namespace securelink {

template <typename F>
class ScopeGuard {
public:
    explicit ScopeGuard(F&& f) noexcept(std::is_nothrow_move_constructible_v<F>)
        : fn_(std::move(f)), active_(true) {}

    ScopeGuard(ScopeGuard&& other) noexcept
        : fn_(std::move(other.fn_)), active_(other.active_) {
        other.active_ = false;
    }

    ~ScopeGuard() noexcept {
        if (active_) {
            try { fn_(); } catch (...) { /* swallow: dtor must not throw */ }
        }
    }

    ScopeGuard(const ScopeGuard&)            = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    ScopeGuard& operator=(ScopeGuard&&)      = delete;

    void dismiss() noexcept { active_ = false; }
    bool active()  const noexcept { return active_; }

private:
    F    fn_;
    bool active_;
};

template <typename F>
[[nodiscard]] ScopeGuard<std::decay_t<F>> make_scope_guard(F&& f) {
    return ScopeGuard<std::decay_t<F>>(std::forward<F>(f));
}

}  // namespace securelink

// Macro convenience. Expands to a uniquely-named guard.
#define SECURELINK_CONCAT_INNER(a, b) a##b
#define SECURELINK_CONCAT(a, b)       SECURELINK_CONCAT_INNER(a, b)
#define SECURELINK_DEFER(code)                                                \
    auto SECURELINK_CONCAT(_sl_guard_, __LINE__) =                            \
        ::securelink::make_scope_guard([&]() { code; })
