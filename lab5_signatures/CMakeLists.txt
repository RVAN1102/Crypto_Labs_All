cmake_minimum_required(VERSION 3.20)

project(Lab5_Signatures_OpenSSL LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(OPENSSL_ROOT_DIR "" CACHE PATH "Optional OpenSSL root directory")
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

set(SIGTOOL_CORE_SOURCES
    src/bench.cpp
    src/cli.cpp
    src/encoding.cpp
    src/file_utils.cpp
    src/signatures.cpp
)

add_library(sigtool_core STATIC ${SIGTOOL_CORE_SOURCES})

target_include_directories(sigtool_core PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(sigtool_core PUBLIC OpenSSL::Crypto)

if(WIN32)
    target_compile_definitions(sigtool_core PUBLIC
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )
endif()

if(MINGW OR CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sigtool_core PRIVATE -Wall -Wextra -O2)
endif()

add_executable(sigtool src/main.cpp)
target_link_libraries(sigtool PRIVATE sigtool_core)

if(WIN32)
    add_custom_command(TARGET sigtool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${PROJECT_SOURCE_DIR}/artifacts/windows/binaries"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:sigtool>" "${PROJECT_SOURCE_DIR}/artifacts/windows/binaries/$<TARGET_FILE_NAME:sigtool>"
    )
endif()

enable_testing()

add_test(NAME sigtool_help COMMAND sigtool --help)
add_test(NAME sigtool_kat COMMAND sigtool kat)
add_test(
    NAME sigtool_cli_requirements
    COMMAND ${CMAKE_COMMAND}
        "-DSIGTOOL=$<TARGET_FILE:sigtool>"
        "-DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/cli-requirements"
        -P "${PROJECT_SOURCE_DIR}/tests/cli_requirements.cmake"
)

find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()

add_executable(sigtool_unit_tests tests/test_sigtool.cpp)
target_link_libraries(sigtool_unit_tests PRIVATE sigtool_core)

if(GTest_FOUND)
    target_compile_definitions(sigtool_unit_tests PRIVATE SIGTOOL_USE_GTEST)
    target_link_libraries(sigtool_unit_tests PRIVATE GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(sigtool_unit_tests)
else()
    add_test(NAME sigtool_unit_tests COMMAND sigtool_unit_tests)
endif()

if(WIN32)
    add_test(
        NAME sigtool_bench_smoke_windows
        COMMAND sigtool bench
            --out "${PROJECT_SOURCE_DIR}/artifacts/windows/bench/bench_windows_smoke_raw.csv"
            --summary "${PROJECT_SOURCE_DIR}/artifacts/windows/bench/bench_windows_smoke_summary.csv"
            --runs 1
            --ops 1
            --sizes 1k
            --algos ecdsa-p256,rsa-pss-3072
            --platform windows-mingw64
    )

    add_test(
        NAME negative_tests_windows
        COMMAND powershell -ExecutionPolicy Bypass -File "${PROJECT_SOURCE_DIR}/scripts/negative_tests_windows.ps1" -Exe "$<TARGET_FILE:sigtool>"
    )
endif()

if(UNIX AND NOT APPLE)
    add_test(
        NAME sigtool_bench_smoke_linux
        COMMAND sigtool bench
            --out "${PROJECT_SOURCE_DIR}/artifacts/linux/bench/bench_linux_smoke_raw.csv"
            --summary "${PROJECT_SOURCE_DIR}/artifacts/linux/bench/bench_linux_smoke_summary.csv"
            --runs 1
            --ops 1
            --sizes 1k
            --algos ecdsa-p256,rsa-pss-3072
            --platform ubuntu-linux
    )

    add_test(
        NAME negative_tests_linux
        COMMAND bash "${PROJECT_SOURCE_DIR}/scripts/negative_tests_linux.sh" "$<TARGET_FILE:sigtool>"
    )
endif()
