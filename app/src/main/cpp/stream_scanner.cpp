#include "stream_scanner.h"

#include <algorithm>
#include <cstring>

namespace alai {
namespace {
constexpr char kSelfTestPattern[] = "ALAI_ENGINE_SELFTEST_MARKER_V1";
constexpr std::size_t kOverlapBytes = sizeof(kSelfTestPattern) - 2U;
}  // namespace

const char* StreamScanner::SelfTestMarker() noexcept {
    return kSelfTestPattern;
}

bool StreamScanner::Update(const std::uint8_t* bytes, std::size_t length) {
    if (finished_ || length > kMaxChunkBytes || (bytes == nullptr && length != 0U)) {
        return false;
    }
    if (matched_ || length == 0U) {
        return true;
    }

    std::string window;
    window.reserve(overlap_.size() + length);
    window.append(overlap_);
    window.append(reinterpret_cast<const char*>(bytes), length);

    if (window.find(kSelfTestPattern) != std::string::npos) {
        matched_ = true;
        overlap_.clear();
        return true;
    }

    const std::size_t keep = std::min(window.size(), kOverlapBytes);
    if (keep == 0U) {
        overlap_.clear();
    } else {
        overlap_.assign(window.data() + (window.size() - keep), keep);
    }
    return true;
}

int StreamScanner::Finish() {
    finished_ = true;
    return matched_ ? kSelfTestMarkerMatch : kNoMatch;
}

std::size_t StreamScanner::RetainedBytesForTest() const noexcept {
    return overlap_.size();
}

}  // namespace alai
