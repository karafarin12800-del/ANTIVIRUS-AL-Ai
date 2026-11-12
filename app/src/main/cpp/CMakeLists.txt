cmake_minimum_required(VERSION 3.22.1)
project(alai_scan_engine LANGUAGES CXX)

add_library(alai_scan_engine SHARED
    stream_scanner.cpp
    jni_bridge.cpp
)

target_include_directories(alai_scan_engine PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(alai_scan_engine PRIVATE cxx_std_17)
target_compile_options(alai_scan_engine PRIVATE
    -Wall
    -Wextra
    -Werror
    -fvisibility=hidden
)
