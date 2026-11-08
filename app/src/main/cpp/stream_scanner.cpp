#include "stream_scanner.h"
#include <algorithm>
#include <cctype>
#include <queue>
namespace alai { namespace {
constexpr char kSelfTestPattern[]="ALAI_ENGINE_SELFTEST_MARKER_V1";
bool ValidRuleId(const std::string& id){if(id.empty()||id.size()>64U)return false;return std::all_of(id.begin(),id.end(),[](unsigned char c){return std::isalnum(c)!=0||c=='.'||c=='_'||c=='-';});}
}
const char* StreamScanner::SelfTestMarker() noexcept{return kSelfTestPattern;}
std::size_t StreamScanner::FindEdge(const Node& n,std::uint8_t b) noexcept {const auto i=std::find_if(n.edges.begin(),n.edges.end(),[b](const auto& e){return e.first==b;});return i==n.edges.end()?static_cast<std::size_t>(-1):i->second;}
bool StreamScanner::AddRule(const std::string& id,const std::uint8_t* p,std::size_t n){
 if(built_||finished_||!ValidRuleId(id)||p==nullptr||n<4U||n>kMaxPatternBytes||rules_.size()>=kMaxRules||totalPatternBytes_>kMaxTotalPatternBytes-n)return false;
 if(std::any_of(rules_.begin(),rules_.end(),[&id](const Rule& r){return r.id==id;}))return false;
 rules_.push_back({id,std::string(reinterpret_cast<const char*>(p),n)});totalPatternBytes_+=n;return true;
}
bool StreamScanner::BuildAutomaton(){
 if (built_) return true;
 nodes_.clear();
 nodes_.emplace_back();
 matched_.assign(rules_.size(), false);
 for(std::size_t ri=0;ri<rules_.size();++ri){std::size_t ni=0;for(unsigned char b:rules_[ri].pattern){std::size_t nx=FindEdge(nodes_[ni],b);if(nx==static_cast<std::size_t>(-1)){if(nodes_.size()>=kMaxNodes)return false;nx=nodes_.size();nodes_.emplace_back();nodes_[ni].edges.emplace_back(b,nx);}ni=nx;}nodes_[ni].outputs.push_back(ri);}
 std::queue<std::size_t> q;for(const auto& e:nodes_[0].edges){nodes_[e.second].failure=0;q.push(e.second);}
 while(!q.empty()){const auto parent=q.front();q.pop();for(const auto& e:nodes_[parent].edges){const std::uint8_t byte=e.first;const std::size_t child=e.second;std::size_t fallback=nodes_[parent].failure;std::size_t candidate=FindEdge(nodes_[fallback],byte);while(fallback!=0U&&candidate==static_cast<std::size_t>(-1)){fallback=nodes_[fallback].failure;candidate=FindEdge(nodes_[fallback],byte);}nodes_[child].failure=(candidate!=static_cast<std::size_t>(-1)&&candidate!=child)?candidate:0U;const auto& inherited=nodes_[nodes_[child].failure].outputs;nodes_[child].outputs.insert(nodes_[child].outputs.end(),inherited.begin(),inherited.end());q.push(child);}}
 built_=true;return true;
}
bool StreamScanner::Update(const std::uint8_t* p,std::size_t n){if(finished_||n>kMaxChunkBytes||(p==nullptr&&n!=0U)||!BuildAutomaton())return false;for(std::size_t i=0;i<n;++i){const auto b=p[i];std::size_t nx=FindEdge(nodes_[state_],b);while(state_!=0U&&nx==static_cast<std::size_t>(-1)){state_=nodes_[state_].failure;nx=FindEdge(nodes_[state_],b);}state_=nx==static_cast<std::size_t>(-1)?0U:nx;for(auto ri:nodes_[state_].outputs)matched_[ri]=true;}return true;}
std::vector<std::string> StreamScanner::Finish(){finished_=true;std::vector<std::string> out;for(std::size_t i=0;i<rules_.size();++i)if(matched_[i])out.push_back(rules_[i].id);return out;}
std::size_t StreamScanner::RetainedBytesForTest() const noexcept{return 0U;}
}
