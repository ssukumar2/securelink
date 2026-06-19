#include "attack_sim.hpp"

#include <chrono>
#include <cstdio>

namespace securelink::attacks {

const char* attack_result_name(AttackResult r) {
    switch (r) {
        case AttackResult::kBlocked:      return "BLOCKED";
        case AttackResult::kDetected:     return "DETECTED";
        case AttackResult::kAllowed:      return "ALLOWED";
        case AttackResult::kInconclusive: return "INCONCLUSIVE";
    }
    return "?";
}

void AttackSim::add(const std::string& name, ScenarioFn fn) {
    scenarios_.push_back({name, std::move(fn)});
}

int AttackSim::run_all(bool verbose) {
    outcomes_.clear();
    int failures = 0;
    for (const auto& s : scenarios_) {
        const auto t0 = std::chrono::steady_clock::now();
        ScenarioOutcome o;
        try {
            o = s.fn();
        } catch (const std::exception& e) {
            o.name     = s.name;
            o.result   = AttackResult::kInconclusive;
            o.evidence = std::string("threw: ") + e.what();
        }
        const auto t1 = std::chrono::steady_clock::now();
        o.duration_us = (std::uint64_t)std::chrono::duration_cast
                            std::chrono::microseconds>(t1 - t0).count();
        if (o.name.empty()) o.name = s.name;

        if (o.result == AttackResult::kAllowed ||
            o.result == AttackResult::kInconclusive) {
            ++failures;
        }
        outcomes_.push_back(std::move(o));

        if (verbose) {
            const auto& back = outcomes_.back();
            std::fprintf(stderr, "  [%-12s] %s  (%lluus)  %s\n",
                         attack_result_name(back.result),
                         back.name.c_str(),
                         (unsigned long long)back.duration_us,
                         back.evidence.c_str());
        }
    }
    return failures;
}

static ScenarioOutcome make(std::string n, AttackResult r, std::string e) {
    ScenarioOutcome o;
    o.name     = std::move(n);
    o.result   = r;
    o.evidence = std::move(e);
    return o;
}

ScenarioOutcome blocked (std::string n, std::string e) {
    return make(std::move(n), AttackResult::kBlocked, std::move(e));
}
ScenarioOutcome detected(std::string n, std::string e) {
    return make(std::move(n), AttackResult::kDetected, std::move(e));
}
ScenarioOutcome allowed (std::string n, std::string e) {
    return make(std::move(n), AttackResult::kAllowed, std::move(e));
}
ScenarioOutcome incon   (std::string n, std::string e) {
    return make(std::move(n), AttackResult::kInconclusive, std::move(e));
}

}  // namespace securelink::attacks
