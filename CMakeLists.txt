cmake_minimum_required(VERSION 3.22)
project(Cipher)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(Cipher
        ciphers.cpp
        ciphers.h
        gtest_lite.h
        memtrace.cpp
        memtrace.h
        test.cpp)
