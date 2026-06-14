cmake_minimum_required(VERSION 3.20)

project(Lab1_AES_CryptoPP LANGUAGES CXX)

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
            include
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

if(NOT EXISTS "${CRYPTOPP_INCLUDE_DIR}/cryptlib.h")
    message(FATAL_ERROR "Crypto++ header not found at ${CRYPTOPP_INCLUDE_DIR}/cryptlib.h")
endif()

if(NOT EXISTS "${CRYPTOPP_LIBRARY}")
    message(FATAL_ERROR "Crypto++ library not found at ${CRYPTOPP_LIBRARY}")
endif()

message(STATUS "Crypto++ include dir: ${CRYPTOPP_INCLUDE_DIR}")
message(STATUS "Crypto++ library: ${CRYPTOPP_LIBRARY}")

enable_testing()

find_package(GTest CONFIG QUIET)

if(NOT GTest_FOUND)
    find_package(GTest REQUIRED)
endif()

add_executable(aestool_unit_tests
    tests/test_crypto_core.cpp
)

target_link_libraries(aestool_unit_tests PRIVATE
    aestool_core
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(aestool_unit_tests)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(AESTOOL_CORE_SOURCES
    src/cli.cpp
    src/encoding.cpp
    src/file_utils.cpp
    src/crypto_utils.cpp
    src/aes_gcm.cpp
    src/aes_ccm.cpp
    src/aes_xts.cpp
    src/aes_classic.cpp
    src/aes_kat.cpp
    src/bench.cpp
    src/metadata.cpp
    src/nonce_registry.cpp
)

add_library(aestool_core STATIC ${AESTOOL_CORE_SOURCES})

target_include_directories(aestool_core PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
    "${CRYPTOPP_INCLUDE_DIR}"
)
target_link_libraries(aestool_core PUBLIC
    "${CRYPTOPP_LIBRARY}"
)

if(WIN32)
    target_compile_definitions(aestool_core PUBLIC
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )

    target_link_libraries(aestool_core PUBLIC
        ws2_32
        advapi32
        bcrypt
    )
endif()

if(MINGW)
    target_compile_options(aestool_core PRIVATE
        -Wall
        -Wextra
        -O3
    )
endif()

add_executable(aestool
    src/main.cpp
)

target_link_libraries(aestool PRIVATE
    aestool_core
)

target_include_directories(aestool PRIVATE
    "${PROJECT_SOURCE_DIR}/include"
    "${CRYPTOPP_INCLUDE_DIR}"
)

target_link_libraries(aestool PRIVATE
    "${CRYPTOPP_LIBRARY}"
)

if(WIN32)
    target_compile_definitions(aestool PRIVATE
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )

    target_link_libraries(aestool PRIVATE
        ws2_32
        advapi32
        bcrypt
    )
endif()

if(MINGW)
    target_compile_options(aestool PRIVATE
        -Wall
        -Wextra
        -O3
    )
endif()

add_test(
    NAME aes_kat_sample
    COMMAND aestool kat --kat "${PROJECT_SOURCE_DIR}/vectors/aes_kat_sample.json"
)

add_test(NAME aes_kat_extended COMMAND aestool kat --kat "${PROJECT_SOURCE_DIR}/vectors/aes_kat_extended.json")

if(WIN32)
    add_test(
        NAME negative_tests_windows
        COMMAND powershell -ExecutionPolicy Bypass -File "${PROJECT_SOURCE_DIR}/scripts/negative_tests_windows.ps1" -Exe "$<TARGET_FILE:aestool>"
    )
endif()

if(UNIX AND NOT APPLE)
    add_test(NAME negative_tests_linux
        COMMAND bash "${PROJECT_SOURCE_DIR}/scripts/negative_tests_linux.sh" "$<TARGET_FILE:aestool>"
    )
endif()
