#include "stream_scanner.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main() {
    const std::string marker = alai::StreamScanner::SelfTestMarker();

    {
        alai::StreamScanner scanner;
        const std::string input = "prefix:" + marker + ":suffix";
        assert(scanner.Update(
            reinterpret_cast<const std::uint8_t*>(input.data()),
            input.size()
        ));
        assert(scanner.Finish() == alai::StreamScanner::kSelfTestMarkerMatch);
    }

    {
        alai::StreamScanner scanner;
        const std::string prefix = "ordinary-prefix";
        const std::string suffix = marker + "-tail";
        assert(scanner.Update(
            reinterpret_cast<const std::uint8_t*>(prefix.data()),
            prefix.size()
        ));
        const std::size_t split = marker.size() / 2U;
        assert(scanner.Update(
            reinterpret_cast<const std::uint8_t*>(marker.data()),
            split
        ));
        assert(scanner.Update(
            reinterpret_cast<const std::uint8_t*>(marker.data() + split),
            marker.size() - split
        ));
        assert(scanner.Update(
            reinterpret_cast<const std::uint8_t*>(suffix.data() + marker.size()),
            suffix.size() - marker.size()
        ));
        assert(scanner.Finish() == alai::StreamScanner::kSelfTestMarkerMatch);
    }

    {
        alai::StreamScanner scanner;
        const std::string input = "ordinary document with no configured marker";
        assert(scanner.Update(
            reinterpret_cast<const std::uint8_t*>(input.data()),
            input.size()
        ));
        assert(scanner.Finish() == alai::StreamScanner::kNoMatch);
        assert(!scanner.Update(reinterpret_cast<const std::uint8_t*>("x"), 1U));
    }

    {
        alai::StreamScanner scanner;
        std::vector<std::uint8_t> chunk(8192U, static_cast<std::uint8_t>('x'));
        for (int i = 0; i < 512; ++i) {
            assert(scanner.Update(chunk.data(), chunk.size()));
            assert(scanner.RetainedBytesForTest() <= marker.size() - 1U);
        }
        assert(scanner.Finish() == alai::StreamScanner::kNoMatch);
    }

    {
        alai::StreamScanner scanner;
        std::vector<std::uint8_t> tooLarge(alai::StreamScanner::kMaxChunkBytes + 1U, 0U);
        assert(!scanner.Update(tooLarge.data(), tooLarge.size()));
    }

    std::cout << "Native stream scanner tests passed.\n";
    return 0;
}
