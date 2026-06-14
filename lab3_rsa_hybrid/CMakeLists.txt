cmake_minimum_required(VERSION 3.20)

project(Lab3_RSA_Hybrid_CryptoPP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CRYPTOPP_ROOT "" CACHE PATH "Crypto++ root directory")
set(CRYPTOPP_INCLUDE_DIR "" CACHE PATH "Crypto++ include directory")
set(CRYPTOPP_LIBRARY "" CACHE FILEPATH "Crypto++ library file")

if(WIN32 AND NOT CRYPTOPP_ROOT)
    set(CRYPTOPP_ROOT "D:/Newfolder/Crypto++" CACHE PATH "Crypto++ root directory" FORCE)
endif()

if(CRYPTOPP_ROOT AND NOT CRYPTOPP_INCLUDE_DIR)
    set(CRYPTOPP_INCLUDE_DIR "${CRYPTOPP_ROOT}")
endif()

if(WIN32 AND CRYPTOPP_ROOT AND NOT CRYPTOPP_LIBRARY)
    set(CRYPTOPP_LIBRARY "${CRYPTOPP_ROOT}/libcryptopp.a")
endif()

if(NOT CRYPTOPP_INCLUDE_DIR)
    find_path(CRYPTOPP_INCLUDE_DIR_DETECTED
        NAMES cryptlib.h
        HINTS
            "${CRYPTOPP_ROOT}"
            /usr
            /usr/local
        PATH_SUFFIXES
            include/cryptopp
            include/crypto++
            cryptopp
            crypto++
    )

    if(CRYPTOPP_INCLUDE_DIR_DETECTED)
        set(CRYPTOPP_INCLUDE_DIR "${CRYPTOPP_INCLUDE_DIR_DETECTED}" CACHE PATH "Crypto++ include directory" FORCE)
    endif()
endif()

if(NOT CRYPTOPP_LIBRARY)
    find_library(CRYPTOPP_LIBRARY_DETECTED
        NAMES cryptopp crypto++ libcryptopp
        HINTS
            "${CRYPTOPP_ROOT}"
            /usr
            /usr/local
        PATH_SUFFIXES
            lib
            lib64
            lib/x86_64-linux-gnu
            lib/aarch64-linux-gnu
    )

    if(CRYPTOPP_LIBRARY_DETECTED)
        set(CRYPTOPP_LIBRARY "${CRYPTOPP_LIBRARY_DETECTED}" CACHE FILEPATH "Crypto++ library file" FORCE)
    endif()
endif()

if(NOT CRYPTOPP_INCLUDE_DIR)
    message(FATAL_ERROR "Crypto++ include directory not found.")
endif()

if(NOT CRYPTOPP_LIBRARY)
    message(FATAL_ERROR "Crypto++ library not found.")
endif()

message(STATUS "Crypto++ include dir: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library: ${CRYPTOPP_LIBRARY}")

set(RSATOOL_CORE_SOURCES
    src/aes_gcm.cpp
    src/bench.cpp
    src/cli.cpp
    src/encoding.cpp
    src/envelope.cpp
    src/file_utils.cpp
    src/kat.cpp
    src/random_utils.cpp
    src/rsa_oaep.cpp
)

add_library(rsatool_core STATIC ${RSATOOL_CORE_SOURCES})

target_include_directories(rsatool_core PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
    "${CRYPTOPP_INCLUDE_DIR}"
)

target_link_libraries(rsatool_core PUBLIC "${CRYPTOPP_LIBRARY}")

if(WIN32)
    target_compile_definitions(rsatool_core PUBLIC
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )

    target_link_libraries(rsatool_core PUBLIC ws2_32 advapi32 bcrypt)
endif()

if(MINGW OR CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(rsatool_core PRIVATE -Wall -Wextra -O2)
endif()

add_executable(rsatool src/main.cpp)
target_link_libraries(rsatool PRIVATE rsatool_core)

enable_testing()

find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest REQUIRED)
endif()

add_executable(rsatool_unit_tests tests/test_rsa_hybrid.cpp)
target_link_libraries(rsatool_unit_tests PRIVATE rsatool_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(rsatool_unit_tests)

add_test(
    NAME rsa_hybrid_kat
    COMMAND rsatool kat --kat "${PROJECT_SOURCE_DIR}/vectors/rsa_hybrid_kat.json"
)

if(WIN32)
    add_test(
        NAME negative_tests_windows
        COMMAND powershell -ExecutionPolicy Bypass -File "${PROJECT_SOURCE_DIR}/scripts/negative_tests_windows.ps1" -Exe "$<TARGET_FILE:rsatool>"
    )
endif()

if(UNIX AND NOT APPLE)
    add_test(
        NAME negative_tests_linux
        COMMAND bash "${PROJECT_SOURCE_DIR}/scripts/negative_tests_linux.sh" "$<TARGET_FILE:rsatool>"
    )
endif()
