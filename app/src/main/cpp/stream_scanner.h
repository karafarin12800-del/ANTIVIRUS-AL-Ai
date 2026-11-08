#ifndef ALAI_STREAM_SCANNER_H_
#define ALAI_STREAM_SCANNER_H_

#include <cstddef>
#include <cstdint>
#include <string>

namespace alai {

class StreamScanner final {
public:
    enum ResultCode : int {
        kNoMatch = 0,
        kSelfTestMarkerMatch = 1,
        kEngineError = -1,
    };

    static constexpr std::size_t kMaxChunkBytes = 64U * 1024U;

    StreamScanner() = default;

    // Accepts one bounded chunk. Data is not retained after Update returns,
    // except for the short suffix needed to detect a marker spanning chunks.
    bool Update(const std::uint8_t* bytes, std::size_t length);

    // Idempotently returns the final result code.
    int Finish();

    // Exposed for native unit tests to prove state is bounded.
    std::size_t RetainedBytesForTest() const noexcept;

    static const char* SelfTestMarker() noexcept;

private:
    std::string overlap_;
    bool matched_ = false;
    bool finished_ = false;
};

}  // namespace alai

#endif  // ALAI_STREAM_SCANNER_H_
