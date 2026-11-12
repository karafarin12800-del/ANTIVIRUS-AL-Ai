#include <jni.h>
#include <cstdint>
#include <new>
#include <string>
#include <vector>
#include "stream_scanner.h"
namespace { alai::StreamScanner* FromHandle(jlong h) noexcept{return h==0?nullptr:reinterpret_cast<alai::StreamScanner*>(static_cast<std::uintptr_t>(h));} }
extern "C" JNIEXPORT jlong JNICALL Java_com_antivirusalai_engine_NativeContentEngine_nativeCreate(JNIEnv*,jobject){auto* s=new(std::nothrow) alai::StreamScanner();return static_cast<jlong>(reinterpret_cast<std::uintptr_t>(s));}
extern "C" JNIEXPORT jboolean JNICALL Java_com_antivirusalai_engine_NativeContentEngine_nativeAddRule(JNIEnv* env,jobject,jlong h,jstring id,jbyteArray pattern){
 auto* s=FromHandle(h);if(!s||!id||!pattern)return JNI_FALSE;const char* raw=env->GetStringUTFChars(id,nullptr);if(!raw)return JNI_FALSE;const std::string name(raw);env->ReleaseStringUTFChars(id,raw);
 const jsize n=env->GetArrayLength(pattern);if(n<4||n>static_cast<jsize>(alai::StreamScanner::kMaxPatternBytes))return JNI_FALSE;std::vector<std::uint8_t> bytes(static_cast<std::size_t>(n));env->GetByteArrayRegion(pattern,0,n,reinterpret_cast<jbyte*>(bytes.data()));if(env->ExceptionCheck()){env->ExceptionClear();return JNI_FALSE;}return s->AddRule(name,bytes.data(),bytes.size())?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jboolean JNICALL Java_com_antivirusalai_engine_NativeContentEngine_nativeUpdate(JNIEnv* env,jobject,jlong h,jbyteArray chunk,jint n){
 auto* s=FromHandle(h);if(!s||!chunk||n<0||n>static_cast<jint>(alai::StreamScanner::kMaxChunkBytes)||n>env->GetArrayLength(chunk))return JNI_FALSE;if(n==0)return s->Update(nullptr,0U)?JNI_TRUE:JNI_FALSE;
 std::vector<std::uint8_t> b(static_cast<std::size_t>(n));env->GetByteArrayRegion(chunk,0,n,reinterpret_cast<jbyte*>(b.data()));if(env->ExceptionCheck()){env->ExceptionClear();return JNI_FALSE;}return s->Update(b.data(),b.size())?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jobjectArray JNICALL Java_com_antivirusalai_engine_NativeContentEngine_nativeFinish(JNIEnv* env,jobject,jlong h){
 auto* s=FromHandle(h);if(!s)return nullptr;const auto matches=s->Finish();jclass cls=env->FindClass("java/lang/String");if(!cls)return nullptr;jobjectArray out=env->NewObjectArray(static_cast<jsize>(matches.size()),cls,nullptr);if(!out)return nullptr;
 for(std::size_t i=0;i<matches.size();++i){jstring v=env->NewStringUTF(matches[i].c_str());if(!v)return nullptr;env->SetObjectArrayElement(out,static_cast<jsize>(i),v);env->DeleteLocalRef(v);}return out;
}
extern "C" JNIEXPORT void JNICALL Java_com_antivirusalai_engine_NativeContentEngine_nativeDestroy(JNIEnv*,jobject,jlong h){delete FromHandle(h);}
