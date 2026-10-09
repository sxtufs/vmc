cmake_minimum_required(VERSION 3.10)

project(VMP C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(VMP_OPCODE_TESTS "Build the host-side native VM opcode tests" OFF)
if(VMP_OPCODE_TESTS)
    find_package(JNI REQUIRED)
    add_executable(vmp_opcode_tests
            tests/vmp_opcode_tests.cpp
            src/vmp_file.cpp
            src/vmp_ir.cpp
            src/interpreter.cpp
            src/interpreter_jni.cpp)
    target_include_directories(vmp_opcode_tests PRIVATE
            ${JNI_INCLUDE_DIRS}
            fuzz/shim
            src)
    target_compile_options(vmp_opcode_tests PRIVATE -g -O1 -fno-omit-frame-pointer)
    target_link_libraries(vmp_opcode_tests PRIVATE ${JNI_LIBRARIES} m pthread)

    # Keep the host runner convenient on machines where libjvm is not in the
    # system loader path. JNI_LIBRARIES is normally an absolute libjvm path.
    set(VMP_OPCODE_JNI_RPATHS "")
    foreach(jni_lib IN LISTS JNI_LIBRARIES)
        if(EXISTS "${jni_lib}")
            get_filename_component(jni_dir "${jni_lib}" DIRECTORY)
            list(APPEND VMP_OPCODE_JNI_RPATHS "${jni_dir}")
        endif()
    endforeach()
    if(VMP_OPCODE_JNI_RPATHS)
        list(REMOVE_DUPLICATES VMP_OPCODE_JNI_RPATHS)
        set_target_properties(vmp_opcode_tests PROPERTIES
                BUILD_RPATH "${VMP_OPCODE_JNI_RPATHS}")
    endif()

    add_custom_target(opcode_tests
            COMMAND $<TARGET_FILE:vmp_opcode_tests>
            DEPENDS vmp_opcode_tests
            USES_TERMINAL)
    return()
endif()

option(VMP_FUZZ "Build the host container-parser fuzz target" OFF)
if(VMP_FUZZ)
    add_executable(vmp_fuzz
            src/vmp_file.cpp
            src/vmp_ir.cpp
            fuzz/vmp_fuzz.cpp)
    target_include_directories(vmp_fuzz PRIVATE fuzz/shim src)
    target_compile_definitions(vmp_fuzz PRIVATE VMP_FUZZ_NO_CUSTOM_MAIN)
    target_compile_options(vmp_fuzz PRIVATE -g -O1 -fno-omit-frame-pointer
            -fsanitize=fuzzer-no-link,address,undefined
            -fno-sanitize-recover=all)
    target_link_options(vmp_fuzz PRIVATE -fsanitize=fuzzer,address,undefined
            -fno-sanitize-recover=all)

    add_executable(vmp_seeds
            src/vmp_file.cpp
            src/vmp_ir.cpp
            fuzz/vmp_fuzz.cpp)
    target_include_directories(vmp_seeds PRIVATE fuzz/shim src)
    target_compile_options(vmp_seeds PRIVATE -g -O1 -fno-omit-frame-pointer
            -fsanitize=address,undefined
            -fno-sanitize-recover=all)
    target_link_options(vmp_seeds PRIVATE -fsanitize=address,undefined
            -fno-sanitize-recover=all)
    return()
endif()

if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(LIBFFI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libffi/install/arm64-v8a)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(LIBFFI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libffi/install/armeabi-v7a)
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(LIBFFI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libffi/install/x86_64)
elseif(ANDROID_ABI STREQUAL "x86")
    set(LIBFFI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libffi/install/x86)
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI} (supported: arm64-v8a, armeabi-v7a, x86_64, x86)")
endif()

if(NOT EXISTS ${LIBFFI_DIR}/lib/libffi.a)
    message(FATAL_ERROR
        "libffi for ${ANDROID_ABI} not found at ${LIBFFI_DIR}/lib/libffi.a - "
        "run ./build_libffi.sh <NDK_ROOT> first, and make sure ${ANDROID_ABI} "
        "is in LIBFFI_ABIS")
endif()

add_library(ffi STATIC IMPORTED)
set_target_properties(ffi PROPERTIES
        IMPORTED_LOCATION ${LIBFFI_DIR}/lib/libffi.a
        INTERFACE_INCLUDE_DIRECTORIES ${LIBFFI_DIR}/include)

add_library(VMP SHARED
        src/vmp.cpp
        src/vmp_file.cpp
        src/interpreter.cpp
        src/interpreter_jni.cpp
        src/vmp_sigblock.cpp
        src/vmp_apk_verify.cpp
        src/vmp_ir.cpp
        src/miniz.c)

target_include_directories(VMP PRIVATE
        ${LIBFFI_DIR}/include)

find_package(Python3 COMPONENTS Interpreter)
if(NOT Python3_Interpreter_FOUND)
    message(FATAL_ERROR "python3 required to run gen_consts.py (SHA-256 constants)")
endif()
set(VMP_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/vmpgen)
add_custom_command(
        OUTPUT ${VMP_GEN_DIR}/vmp_sha256_consts.h
        COMMAND ${CMAKE_COMMAND} -E make_directory ${VMP_GEN_DIR}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_consts.py
                ${VMP_GEN_DIR}/vmp_sha256_consts.h
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_consts.py
        COMMENT "Generating self-verified SHA-256 constant tables")
add_custom_target(vmp_consts DEPENDS ${VMP_GEN_DIR}/vmp_sha256_consts.h)
add_dependencies(VMP vmp_consts)
target_include_directories(VMP PRIVATE ${VMP_GEN_DIR})

target_compile_options(VMP PRIVATE -ffunction-sections -fdata-sections)
target_link_options(VMP PRIVATE -Wl,--gc-sections -Wl,-z,max-page-size=16384)
target_link_libraries(VMP
        ffi
        android
        log)

option(VMP_QUIET_LOGS "Strip INFO diagnostics from the shipped .so" ON)
if(VMP_QUIET_LOGS)
    target_compile_definitions(VMP PRIVATE VMP_RELEASE_QUIET)
endif()

target_compile_options(VMP PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)

if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_compile_options(VMP PRIVATE -mbranch-protection=standard)
endif()

target_link_options(VMP PRIVATE -Wl,--exclude-libs,ALL)

target_compile_options(VMP PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
        $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)

if(VMP_QUIET_LOGS)
    target_link_options(VMP PRIVATE -Wl,-s)

    target_compile_options(VMP PRIVATE
            -fno-unwind-tables -fno-asynchronous-unwind-tables)
    target_link_options(VMP PRIVATE -Wl,--no-eh-frame-hdr)
endif()
