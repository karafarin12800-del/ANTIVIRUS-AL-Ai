#include "stream_scanner.h"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
int main(){
 const std::string a="CONTENT_RULE_TEST_42",b="ALAI_ENGINE_SELFTEST_MARKER_V1";
 {alai::StreamScanner s;assert(s.AddRule("RULE-A",reinterpret_cast<const std::uint8_t*>(a.data()),a.size()));std::string x="pre"+a+"post";assert(s.Update(reinterpret_cast<const std::uint8_t*>(x.data()),x.size()));auto m=s.Finish();assert(m.size()==1&&m[0]=="RULE-A");}
 {alai::StreamScanner s;assert(s.AddRule("SELFTEST",reinterpret_cast<const std::uint8_t*>(b.data()),b.size()));auto n=b.size()/2;assert(s.Update(reinterpret_cast<const std::uint8_t*>(b.data()),n));assert(s.Update(reinterpret_cast<const std::uint8_t*>(b.data()+n),b.size()-n));auto m=s.Finish();assert(m.size()==1&&m[0]=="SELFTEST");}
 {alai::StreamScanner s;std::string x="ABCDEF",y="DEFGHI",z="xxABCDEFGHIyy";assert(s.AddRule("A",reinterpret_cast<const std::uint8_t*>(x.data()),x.size()));assert(s.AddRule("B",reinterpret_cast<const std::uint8_t*>(y.data()),y.size()));assert(s.Update(reinterpret_cast<const std::uint8_t*>(z.data()),z.size()));assert(s.Finish().size()==2);}
 {alai::StreamScanner s;std::string x="ordinary document";assert(s.Update(reinterpret_cast<const std::uint8_t*>(x.data()),x.size()));assert(s.Finish().empty());assert(!s.Update(reinterpret_cast<const std::uint8_t*>("x"),1));}
 {alai::StreamScanner s;std::vector<std::uint8_t> x(8192,'x');for(int i=0;i<512;++i){assert(s.Update(x.data(),x.size()));assert(s.RetainedBytesForTest()==0);}assert(s.Finish().empty());}
 {alai::StreamScanner s;std::string x="four";assert(!s.AddRule("short",reinterpret_cast<const std::uint8_t*>(x.data()),3));std::vector<std::uint8_t> xlarge(alai::StreamScanner::kMaxChunkBytes+1,0);assert(!s.Update(xlarge.data(),xlarge.size()));}
 std::cout<<"Native multi-pattern stream scanner tests passed.\n";
}
