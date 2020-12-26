cmake_minimum_required (VERSION 3.5)
# option() honors normal variables.
# see: https://cmake.org/cmake/help/git-stage/policy/CMP0077.html
if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()
# Honor symbol visibility properties for all target types.
# see: https://cmake.org/cmake/help/git-stage/policy/CMP0063.html
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif()

project(kyber C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    set(CMAKE_GENERATOR_CC cl)
    message("  In case of linkage problems be sure to select the proper architecture, e.g. via 'cmake -A x64 ..'")
    message("  In case of runtime problems be sure to select Release config to avoid dev-dll problems, e.g. via 'msbuild ALL_BUILD.vcxproj /property:Configuration=Release'")
    message("  In case of test problems be sure to output error messages, e.g., via 'ctest --output-on-failure -C Release'")
else()
include(FindUnixCommands)
endif()

# find openssl installation for test vector generation
if(NOT DEFINED OPENSSL_ROOT_DIR)
        if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin")
            set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1")
        elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
            set(OPENSSL_ROOT_DIR "/usr")
        endif()
endif()
find_package(OpenSSL 1.1.1 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

enable_testing()

# Kyber ID->"name" mapping
set (K2 512)
set (K3 768)
set (K4 1024)

add_subdirectory(ref)
# For the time being, don't build AVX2 on Win (ToDo!):
if(NOT WIN32)
add_subdirectory(avx2)
endif()

add_library(kyber ${REF_OBJS} ${AVX2_OBJS})

set(PUBLIC_HEADERS ${PROJECT_SOURCE_DIR}/ref/sign.h)

set_target_properties(kyber
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    VERSION 0.1.0
    SOVERSION 0
    # For Windows DLLs
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

install(TARGETS kyber
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)

install(FILES ${PUBLIC_HEADERS}
        DESTINATION include/kyber)


get_property(isMultiConfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

if(isMultiConfig)
    if(NOT "Asan" IN_LIST CMAKE_CONFIGURATION_TYPES)
        list(APPEND CMAKE_CONFIGURATION_TYPES Asan)
    endif()
else()
    set(allowedBuildTypes Asan Debug Release RelWithDebInfo MinSizeRel)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "${allowedBuildTypes}")

    if(CMAKE_BUILD_TYPE AND NOT CMAKE_BUILD_TYPE IN_LIST allowedBuildTypes)
        message(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}")
    endif()
endif()

set(CMAKE_C_FLAGS_ASAN
    "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer" CACHE STRING
    "Flags used by the C compiler for Asan build type or configuration." FORCE)

set(CMAKE_CXX_FLAGS_ASAN
    "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer" CACHE STRING
    "Flags used by the C++ compiler for Asan build type or configuration." FORCE)

set(CMAKE_EXE_LINKER_FLAGS_ASAN
    "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address" CACHE STRING
    "Linker flags to be used to create executables for Asan build type." FORCE)

set(CMAKE_SHARED_LINKER_FLAGS_ASAN
    "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address" CACHE STRING
    "Linker lags to be used to create shared libraries for Asan build type." FORCE)
