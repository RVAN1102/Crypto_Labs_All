cmake_minimum_required(VERSION 3.20)
project(Lab6_PQC_OpenSSL LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not supported. Use cmake -S . -B build-linux.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)

set(PQTOOL_CORE_SOURCES
    src/bench.cpp
    src/cli.cpp
    src/encoding.cpp
    src/errors.cpp
    src/file_io.cpp
    src/json_canonical.cpp
    src/mldsa.cpp
    src/mlkem.cpp
    src/openssl_utils.cpp
    src/pq_cert.cpp
    src/pq_key.cpp
)

add_library(pqtool_core STATIC ${PQTOOL_CORE_SOURCES})
target_include_directories(pqtool_core PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(pqtool_core PUBLIC OpenSSL::Crypto)

if(MSVC)
    target_compile_options(pqtool_core PRIVATE /W4)
    target_compile_definitions(pqtool_core PUBLIC NOMINMAX _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(pqtool_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(pqtool src/main.cpp)
target_link_libraries(pqtool PRIVATE pqtool_core)

enable_testing()
add_subdirectory(tests)

