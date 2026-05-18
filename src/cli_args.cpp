#include "cli_args.hpp"

#include <cstdlib>
#include <stdexcept>
#include <string_view>

namespace securelink {

CliArgs::CliArgs(int argc, char** argv,
                 const std::unordered_set<std::string>& boolean_flags) {
    if (argc > 0 && argv[0] != nullptr) program_ = argv[0];

    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        if (a.size() < 2 || a.substr(0, 2) != "--") {
            positionals_.emplace_back(a);
            continue;
        }
        std::string_view body = a.substr(2);
        const auto eq = body.find('=');

        if (eq != std::string_view::npos) {
            std::string name(body.substr(0, eq));
            std::string val (body.substr(eq + 1));
            if (boolean_flags.count(name)) {
                throw CliError("boolean flag --" + name + " takes no value");
            }
            values_[std::move(name)] = std::move(val);
            continue;
        }

        std::string name(body);
        if (boolean_flags.count(name)) {
            flags_.insert(std::move(name));
            continue;
        }
        if (i + 1 >= argc) {
            throw CliError("missing value for --" + name);
        }
        values_[std::move(name)] = argv[++i];
    }
}

std::optional<std::string> CliArgs::get(const std::string& name) const {
    auto it = values_.find(name);
    if (it == values_.end()) return std::nullopt;
    return it->second;
}

bool CliArgs::flag(const std::string& name) const {
    return flags_.count(name) > 0;
}

std::string CliArgs::get_string(const std::string& name, std::string fb) const {
    auto v = get(name);
    return v ? *v : std::move(fb);
}

int CliArgs::get_int(const std::string& name, int fb) const {
    auto v = get(name);
    if (!v) return fb;
    try { return std::stoi(*v); }
    catch (...) { throw CliError("invalid integer for --" + name); }
}

std::uint32_t CliArgs::get_u32(const std::string& name, std::uint32_t fb) const {
    auto v = get(name);
    if (!v) return fb;
    try {
        const unsigned long u = std::stoul(*v);
        return static_cast<std::uint32_t>(u);
    } catch (...) {
        throw CliError("invalid u32 for --" + name);
    }
}

std::uint64_t CliArgs::get_u64(const std::string& name, std::uint64_t fb) const {
    auto v = get(name);
    if (!v) return fb;
    try {
        return static_cast<std::uint64_t>(std::stoull(*v));
    } catch (...) {
        throw CliError("invalid u64 for --" + name);
    }
}

}  // namespace securelink
