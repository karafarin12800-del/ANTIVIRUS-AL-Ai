#include <jni.h>

#include <cstdint>
#include <new>
#include <vector>

#include "stream_scanner.h"

namespace {
alai::StreamScanner* FromHandle(jlong handle) noexcept {
    if (handle == 0) {
        return nullptr;
    }
    return reinterpret_cast<alai::StreamScanner*>(static_cast<std::uintptr_t>(handle));
}
}  // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_com_antivirusalai_engine_NativeContentEngine_nativeCreate(
    JNIEnv* /*env*/, jobject /*thiz*/) {
    auto* scanner = new (std::nothrow) alai::StreamScanner();
    return static_cast<jlong>(reinterpret_cast<std::uintptr_t>(scanner));
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_antivirusalai_engine_NativeContentEngine_nativeUpdate(
    JNIEnv* env, jobject /*thiz*/, jlong handle, jbyteArray chunk, jint length) {
    auto* scanner = FromHandle(handle);
    if (scanner == nullptr || chunk == nullptr || length < 0 ||
        length > static_cast<jint>(alai::StreamScanner::kMaxChunkBytes) ||
        length > env->GetArrayLength(chunk)) {
        return JNI_FALSE;
    }
    if (length == 0) {
        return scanner->Update(nullptr, 0U) ? JNI_TRUE : JNI_FALSE;
    }

    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(length));
    env->GetByteArrayRegion(
        chunk,
        0,
        length,
        reinterpret_cast<jbyte*>(buffer.data())
    );
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return JNI_FALSE;
    }

    return scanner->Update(buffer.data(), buffer.size()) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_antivirusalai_engine_NativeContentEngine_nativeFinish(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    auto* scanner = FromHandle(handle);
    return scanner == nullptr ? alai::StreamScanner::kEngineError : scanner->Finish();
}

extern "C" JNIEXPORT void JNICALL
Java_com_antivirusalai_engine_NativeContentEngine_nativeDestroy(
    JNIEnv* /*env*/, jobject /*thiz*/, jlong handle) {
    delete FromHandle(handle);
}
