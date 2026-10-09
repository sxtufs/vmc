#ifndef VMP_LOG_H
#define VMP_LOG_H

#include <android/log.h>

/**
 * Single logging policy for every native translation unit.
 *
 *   LOGI     - INFO diagnostics (instruction trace, init banners). Compiled out
 *              of quiet builds entirely - no code and no format strings.
 *   LOGDIAG  - heuristic / expected-failure notes that fire on normal app
 *              behavior. Compiled out of quiet builds; WARN otherwise.
 *   LOGE     - crash breadcrumbs. Always live, always PLAINTEXT.
 *
 * LOGE remains plaintext because the current compiler keeps these literals in
 * .rodata even when compile-time string encryption is enabled. Any change to
 * this policy must be verified against the built .so.
 *
 * The loader entry-point name and JNI signature are XOR-encoded and decoded
 * into stack buffers during JNI_OnLoad. The source representation and the
 * built binary must remain aligned.
 *
 * These messages expose limited runtime structure; plaintext application strings
 * in the container are a larger exposure.
 *
 * Full-diagnostic build: cmake -DVMP_QUIET_LOGS=OFF (see native/CMakeLists.txt).
 */

#define LOG_TAG "VMP"

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifdef VMP_RELEASE_QUIET
#define LOGI(...) ((void)0)
#define LOGDIAG(...) ((void)0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGDIAG(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#endif

#endif // VMP_LOG_H
