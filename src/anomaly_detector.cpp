#include "anomaly_detector.hpp"

#include <cassert>
#include <cmath>

namespace securelink {

AnomalyDetector::AnomalyDetector(double alpha,
                                 double z_threshold,
                                 std::uint64_t warmup_samples)
    : alpha_(alpha),
      z_threshold_(z_threshold),
      warmup_(warmup_samples) {
    // These two parameters are both `double` with no way for the
    // compiler to catch a caller accidentally swapping them -- and a
    // swap wouldn'''t crash, it would silently misconfigure the detector
    // (alpha clamped to 1.0 means no smoothing at all; z_threshold this
    // low means nearly everything reads as anomalous). The clamps below
    // already existed to handle genuinely-out-of-range input; asserting
    // first makes a swap (or any other implausible config) loud in
    // debug/test builds instead of quietly "fixing" it and moving on.
    assert(alpha > 0.0 && alpha <= 1.0 &&
           "alpha out of (0,1] range -- check this isn'''t swapped with z_threshold");
    assert(z_threshold > 0.0 &&
           "z_threshold must be positive -- check this isn'''t swapped with alpha");

    if (alpha_ <= 0.0)        alpha_ = 1e-6;
    if (alpha_ >  1.0)        alpha_ = 1.0;
    if (z_threshold_ <= 0.0)  z_threshold_ = 3.0;
}

bool AnomalyDetector::observe(double value) {
    last_ = value;
    ++n_;

    if (n_ == 1) {
        mean_ = value;
        var_  = 0.0;
        last_z_ = 0.0;
        return false;
    }

    // Score this observation against the statistics as they stood BEFORE
    // this sample. Updating mean_/var_ first would let a large outlier
    // inflate its own sigma and hide from the very z-score meant to
    // catch it -- the outlier would poison the baseline used to judge it.
    const double diff = value - mean_;
    const double sigma_before = std::sqrt(var_);
    last_z_ = (sigma_before > 0.0) ? (diff / sigma_before) : 0.0;

    // Now fold this sample into the running mean/variance for next time.
    const double incr = alpha_ * diff;
    mean_ += incr;
    var_  = (1.0 - alpha_) * (var_ + alpha_ * diff * diff);

    if (n_ <= warmup_) return false;
    const bool anomalous = std::fabs(last_z_) > z_threshold_;
    if (anomalous) ++anomalies_;
    return anomalous;
}

void AnomalyDetector::reset() {
    mean_ = var_ = last_ = last_z_ = 0.0;
    n_ = anomalies_ = 0;
}

}  // namespace securelink
