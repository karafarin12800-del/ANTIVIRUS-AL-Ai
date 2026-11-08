#ifndef ALAI_STREAM_SCANNER_H_
#define ALAI_STREAM_SCANNER_H_
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>
namespace alai {
class StreamScanner final {
public:
 static constexpr std::size_t kMaxChunkBytes=64U*1024U, kMaxRules=512U, kMaxPatternBytes=256U, kMaxTotalPatternBytes=64U*1024U;
 StreamScanner()=default;
 bool AddRule(const std::string&,const std::uint8_t*,std::size_t);
 bool Update(const std::uint8_t*,std::size_t);
 std::vector<std::string> Finish();
 std::size_t RetainedBytesForTest() const noexcept;
 static const char* SelfTestMarker() noexcept;
private:
 struct Rule { std::string id; std::string pattern; };
 struct Node { std::vector<std::pair<std::uint8_t,std::size_t>> edges; std::size_t failure=0U; std::vector<std::size_t> outputs; };
 static constexpr std::size_t kMaxNodes=65'536U;
 std::vector<Rule> rules_; std::vector<Node> nodes_; std::vector<bool> matched_;
 std::size_t totalPatternBytes_=0U,state_=0U; bool built_=false,finished_=false;
 static std::size_t FindEdge(const Node&,std::uint8_t) noexcept;
 bool BuildAutomaton();
};
}
#endif
