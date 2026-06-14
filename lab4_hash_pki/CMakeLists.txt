cmake_minimum_required(VERSION 3.20)

project(Lab4_Hash_PKI_OpenSSL LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

set(HASHTOOL_CORE_SOURCES
    src/cert.cpp
    src/cli.cpp
    src/encoding.cpp
    src/file_utils.cpp
    src/hash.cpp
    src/kat.cpp
    src/mac.cpp
)

add_library(hashtool_core STATIC ${HASHTOOL_CORE_SOURCES})

target_include_directories(hashtool_core PUBLIC
    "${PROJECT_SOURCE_DIR}/include"
)

target_link_libraries(hashtool_core PUBLIC OpenSSL::Crypto)

if(WIN32)
    target_compile_definitions(hashtool_core PUBLIC
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )
endif()

if(MINGW OR CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(hashtool_core PRIVATE -Wall -Wextra -O2)
endif()

add_executable(hashtool src/main.cpp)
target_link_libraries(hashtool PRIVATE hashtool_core)

if(WIN32)
    add_custom_command(TARGET hashtool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${PROJECT_SOURCE_DIR}/artifacts/windows/binaries"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:hashtool>" "${PROJECT_SOURCE_DIR}/artifacts/windows/binaries/$<TARGET_FILE_NAME:hashtool>"
    )
endif()

enable_testing()

add_test(NAME hashtool_help COMMAND hashtool --help)

add_test(
    NAME hashtool_kat_hash
    COMMAND hashtool kat --kat "${PROJECT_SOURCE_DIR}/vectors/hash_kat.json"
)

add_test(
    NAME hashtool_kat_shake
    COMMAND hashtool kat --kat "${PROJECT_SOURCE_DIR}/vectors/shake_kat.json"
)

add_test(
    NAME cert_info_valid_pem
    COMMAND hashtool cert-info --cert "${PROJECT_SOURCE_DIR}/tests/certs/leaf_valid.pem"
)

add_test(
    NAME cert_info_valid_der
    COMMAND hashtool cert-info --cert "${PROJECT_SOURCE_DIR}/tests/certs/leaf_valid.der" --format der
)

add_test(
    NAME cert_info_malformed_rejected
    COMMAND hashtool cert-info --cert "${PROJECT_SOURCE_DIR}/tests/certs/malformed_cert.pem"
)
set_tests_properties(cert_info_malformed_rejected PROPERTIES WILL_FAIL TRUE)

add_test(
    NAME cert_verify_correct_issuer
    COMMAND hashtool cert-verify --cert "${PROJECT_SOURCE_DIR}/tests/certs/leaf_valid.pem" --issuer "${PROJECT_SOURCE_DIR}/tests/certs/test_ca.pem"
)

add_test(
    NAME cert_verify_wrong_issuer_fails
    COMMAND hashtool cert-verify --cert "${PROJECT_SOURCE_DIR}/tests/certs/leaf_valid.pem" --issuer "${PROJECT_SOURCE_DIR}/tests/certs/wrong_ca.pem"
)
set_tests_properties(cert_verify_wrong_issuer_fails PROPERTIES WILL_FAIL TRUE)

add_test(
    NAME cert_policy_missing_san_flagged
    COMMAND powershell -ExecutionPolicy Bypass -File "${PROJECT_SOURCE_DIR}/scripts/assert_output_contains_windows.ps1" -Exe "$<TARGET_FILE:hashtool>" -Args "cert-policy --cert ${PROJECT_SOURCE_DIR}/tests/certs/leaf_no_san.pem" -Needle "CHECK tls_server_san FAIL"
)

add_test(
    NAME cert_policy_weak_key_flagged
    COMMAND powershell -ExecutionPolicy Bypass -File "${PROJECT_SOURCE_DIR}/scripts/assert_output_contains_windows.ps1" -Exe "$<TARGET_FILE:hashtool>" -Args "cert-policy --cert ${PROJECT_SOURCE_DIR}/tests/certs/leaf_weak.pem" -Needle "CHECK public_key_strength WARN"
)

add_test(
    NAME cert_policy_expired_flagged
    COMMAND powershell -ExecutionPolicy Bypass -File "${PROJECT_SOURCE_DIR}/scripts/assert_output_contains_windows.ps1" -Exe "$<TARGET_FILE:hashtool>" -Args "cert-policy --cert ${PROJECT_SOURCE_DIR}/tests/certs/expired_leaf.pem" -Needle "CHECK validity_not_after FAIL"
)

find_package(GTest CONFIG QUIET)
if(NOT GTest_FOUND)
    find_package(GTest QUIET)
endif()

add_executable(hashtool_unit_tests tests/test_hash_core.cpp)
target_link_libraries(hashtool_unit_tests PRIVATE hashtool_core)

if(GTest_FOUND)
    target_compile_definitions(hashtool_unit_tests PRIVATE HASHTOOL_USE_GTEST)
    target_link_libraries(hashtool_unit_tests PRIVATE GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(hashtool_unit_tests)
else()
    add_test(NAME hashtool_unit_tests COMMAND hashtool_unit_tests)
endif()

if(WIN32)
    add_test(
        NAME negative_tests_windows
        COMMAND powershell -ExecutionPolicy Bypass -File "${PROJECT_SOURCE_DIR}/scripts/negative_tests_windows.ps1" -Exe "$<TARGET_FILE:hashtool>"
    )
endif()
